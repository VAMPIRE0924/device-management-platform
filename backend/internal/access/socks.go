package access

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

var errSOCKSProxyUnavailable = errors.New("SOCKS5 proxy unavailable")

type SOCKSDialer struct {
	ProxyAddress string
	Username     string
	Password     string
	Timeout      time.Duration
}

func (d SOCKSDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("SOCKS5 only supports TCP, got %q", network)
	}
	if d.ProxyAddress == "" {
		return nil, errors.New("SOCKS5 proxy address is required")
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", d.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSOCKSProxyUnavailable, err)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := d.negotiate(conn, address); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	success = true
	return conn, nil
}

func (d SOCKSDialer) negotiate(conn net.Conn, address string) error {
	methods := []byte{0x00}
	if d.Username != "" || d.Password != "" {
		methods = []byte{0x02}
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("send SOCKS5 greeting: %w", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if response[0] != 0x05 || response[1] == 0xff {
		return errors.New("SOCKS5 proxy rejected authentication methods")
	}
	if response[1] == 0x02 {
		if err := d.authenticate(conn); err != nil {
			return err
		}
	} else if response[1] != 0x00 {
		return fmt.Errorf("SOCKS5 proxy selected unsupported authentication method %d", response[1])
	}

	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("target port must be between 1 and 65535")
	}
	request := []byte{0x05, 0x01, 0x00}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			request = append(request, 0x01)
			request = append(request, ip.AsSlice()...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.AsSlice()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return errors.New("target host length must be between 1 and 255 bytes")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("send SOCKS5 connect request: %w", err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read SOCKS5 connect response: %w", err)
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed with status %d", header[1])
	}
	if err := discardSOCKSAddress(conn, header[3]); err != nil {
		return err
	}
	return nil
}

func (d SOCKSDialer) authenticate(conn net.Conn) error {
	if len(d.Username) > 255 || len(d.Password) > 255 {
		return errors.New("SOCKS5 username and password must not exceed 255 bytes")
	}
	request := []byte{0x01, byte(len(d.Username))}
	request = append(request, d.Username...)
	request = append(request, byte(len(d.Password)))
	request = append(request, d.Password...)
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("send SOCKS5 credentials: %w", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read SOCKS5 authentication response: %w", err)
	}
	if response[0] != 0x01 || response[1] != 0x00 {
		return errors.New("SOCKS5 authentication failed")
	}
	return nil
}

func discardSOCKSAddress(reader io.Reader, addressType byte) error {
	length := 0
	switch addressType {
	case 0x01:
		length = 4
	case 0x04:
		length = 16
	case 0x03:
		buffer := []byte{0}
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return fmt.Errorf("read SOCKS5 bound host length: %w", err)
		}
		length = int(buffer[0])
	default:
		return fmt.Errorf("SOCKS5 proxy returned unsupported address type %d", addressType)
	}
	buffer := make([]byte, length+2)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return fmt.Errorf("read SOCKS5 bound address: %w", err)
	}
	return nil
}
