package auth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type EmailSender interface {
	SendCode(context.Context, string, string, time.Duration) error
}

type SMTPConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	From       string
	TLSMode    string
	ServerName string
	RootCAs    *x509.CertPool
}

type SMTPEmailSender struct {
	config SMTPConfig
}

func NewSMTPEmailSender(config SMTPConfig) (*SMTPEmailSender, error) {
	if strings.TrimSpace(config.Host) == "" || config.Port < 1 || config.Port > 65535 {
		return nil, fmt.Errorf("invalid SMTP address")
	}
	if _, err := mail.ParseAddress(config.From); err != nil {
		return nil, fmt.Errorf("invalid SMTP from address: %w", err)
	}
	if config.TLSMode != "starttls" && config.TLSMode != "tls" {
		return nil, fmt.Errorf("invalid SMTP TLS mode")
	}
	if config.ServerName == "" {
		config.ServerName = config.Host
	}
	return &SMTPEmailSender{config: config}, nil
}

func NewEmailCode() (string, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	value := uint32(random[0])<<24 | uint32(random[1])<<16 | uint32(random[2])<<8 | uint32(random[3])
	return fmt.Sprintf("%06d", value%1_000_000), nil
}

func NormalizeEmail(value string) (string, error) {
	address, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil || address.Address == "" || !strings.Contains(address.Address, "@") {
		return "", fmt.Errorf("invalid email address")
	}
	return strings.ToLower(address.Address), nil
}

func MaskEmail(value string) string {
	parts := strings.Split(value, "@")
	if len(parts) != 2 || len(parts[0]) < 2 {
		return "***"
	}
	return parts[0][:1] + strings.Repeat("*", min(6, len(parts[0])-1)) + "@" + parts[1]
}

func (sender *SMTPEmailSender) SendCode(ctx context.Context, recipient, code string, ttl time.Duration) error {
	to, err := NormalizeEmail(recipient)
	if err != nil {
		return err
	}
	from, _ := mail.ParseAddress(sender.config.From)
	address := net.JoinHostPort(sender.config.Host, strconv.Itoa(sender.config.Port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	var connection net.Conn
	if sender.config.TLSMode == "tls" {
		connection, err = tls.DialWithDialer(&dialer, "tcp", address, sender.tlsConfig())
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("connect SMTP server: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	client, err := smtp.NewClient(connection, sender.config.ServerName)
	if err != nil {
		return fmt.Errorf("start SMTP client: %w", err)
	}
	defer client.Close()
	if sender.config.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not support STARTTLS")
		}
		if err := client.StartTLS(sender.tlsConfig()); err != nil {
			return fmt.Errorf("start SMTP TLS: %w", err)
		}
	}
	if sender.config.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", sender.config.Username, sender.config.Password, sender.config.ServerName)); err != nil {
			return fmt.Errorf("authenticate SMTP client: %w", err)
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("set SMTP sender: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("set SMTP recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("open SMTP message: %w", err)
	}
	minutes := int(ttl.Round(time.Minute) / time.Minute)
	subject := mime.QEncoding.Encode("UTF-8", "I5CLOUD 登录验证码")
	body := fmt.Sprintf("您的 I5CLOUD 登录验证码是：%s\r\n\r\n验证码 %d 分钟内有效。若非本人操作，请忽略本邮件。\r\n", code, minutes)
	message := "From: " + sender.config.From + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + body
	if _, err := writer.Write([]byte(message)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("quit SMTP client: %w", err)
	}
	return nil
}

func (sender *SMTPEmailSender) tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: sender.config.ServerName, RootCAs: sender.config.RootCAs}
}
