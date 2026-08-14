package access

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKSDialerAuthenticatedIPv4(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err != nil {
			done <- err
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x02})
		auth := make([]byte, 2)
		_, _ = io.ReadFull(conn, auth)
		username := make([]byte, int(auth[1]))
		_, _ = io.ReadFull(conn, username)
		passwordLength := []byte{0}
		_, _ = io.ReadFull(conn, passwordLength)
		password := make([]byte, int(passwordLength[0]))
		_, _ = io.ReadFull(conn, password)
		if string(username) != "user" || string(password) != "pass" {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, _ = conn.Write([]byte{0x01, 0x00})
		connect := make([]byte, 10)
		_, _ = io.ReadFull(conn, connect)
		if connect[3] != 0x01 || net.IP(connect[4:8]).String() != "192.168.10.1" || binary.BigEndian.Uint16(connect[8:]) != 9443 {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
		done <- nil
	}()

	dialer := SOCKSDialer{ProxyAddress: listener.Addr().String(), Username: "user", Password: "pass", Timeout: time.Second}
	conn, err := dialer.DialContext(t.Context(), "tcp", "192.168.10.1:9443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSOCKSDialerRejectsAuthentication(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	dialer := SOCKSDialer{ProxyAddress: "unused"}
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 3)
		_, _ = io.ReadFull(server, buffer)
		_, _ = server.Write([]byte{0x05, 0xff})
		done <- nil
	}()
	if err := dialer.negotiate(client, "192.168.1.1:80"); err == nil {
		t.Fatal("expected method rejection")
	}
	<-done
}
