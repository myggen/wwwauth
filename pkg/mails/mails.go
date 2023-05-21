package mails

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
)

// Message - Smtp mail message
type Message struct {
	From     string
	To       []string
	Subject  string
	Body     string
	User     string
	Password string
	Server   string
	Port     int16
}

func SendMailNoTLS(m Message) error {

	msg := []byte("" +
		"Subject: " + m.Subject + "\r\n" +
		"\r\n" +
		m.Body + "\r\n")

	if m.From == "" {
		m.From = "noreply"
	}

	if m.Port == 0 {
		m.Port = 25
	}

	if m.Server == "" {
		m.Server = "smtp.met.no"
	}
	serverandport := fmt.Sprintf("%s:%d", m.Server, m.Port)

	err := smtp.SendMail(serverandport, nil, "noreply", m.To, msg)
	if err != nil {
		return err
	}

	return nil

}

func SendMail(m Message) error {

	body := m.Body

	m.Server = "smtp.met.no"
	m.Port = 25
	// Setup headers
	headers := make(map[string]string)
	headers["From"] = m.From
	headers["Subject"] = m.Subject
	headers["MIME-version"] = "1.0"
	headers["Content-Type"] = "text/plain; charset=UTF-8"

	// Setup message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	// Connect to the SMTP Server
	servername := fmt.Sprintf("%s:%d", m.Server, m.Port)

	host, _, _ := net.SplitHostPort(servername)

	auth := smtp.PlainAuth("", m.User, m.Password, host)

	// TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         m.Server,
	}

	// Here is the key, you need to call tls.Dial instead of smtp.Dial
	// for smtp servers running on 465 that require an ssl connection
	// from the very beginning (no starttls)
	conn, err := tls.Dial("tcp", servername, tlsconfig)
	if err != nil {
		return err
	}

	c, err := smtp.NewClient(conn, m.Server)
	if err != nil {
		return err
	}

	// Auth
	if err = c.Auth(auth); err != nil {
		return err
	}

	// To && From
	if err = c.Mail(m.From); err != nil {
		return err
	}
	if len(m.To) > 1 {
		for t := 1; t < len(m.To); t++ {
			if err = c.Rcpt(m.To[t]); err != nil {
				return err
			}
		}
	}
	// Data
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	c.Quit()
	return nil
}
