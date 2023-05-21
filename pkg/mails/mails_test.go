package mails

import (
	"testing"
)

func TestMailsIntegration(t *testing.T) {

	/*
		if testing.Short() {
			t.Skip("skipping integration test")
		}
		if os.Getenv("SMTP_USER") == "" {
			t.Errorf("Missing required environment variable SMTP_USER")
		}
		if os.Getenv("SMTP_PASSORD") == "" {
			t.Errorf("Missing required environment variable SMTP_PASSWORD")
		}
		if os.Getenv("SMTP_SERVER") == "" {
			t.Errorf("Missing required environment variable SMTP_SERVER")
		}
	*/

	message := Message{
		From:    "any@anyany.xyz",
		To:      []string{"espen@toycompute.net", "espenmyr@gmail.com"},
		Subject: "Modifisert programvare",
		Body: `

		ZZZZCC   Har vi ekstern kildekode (åpen) som vi har gjort modifikasjoner på, 
		og som vi ikke har fått godkjent tilbake inn i kilden? I så fall bør 
		vi ha en oversikt over slikeher:
		 `,
		Server: "mail.privateemail.com",
		Port:   465,
	}

	err := SendMail(message)
	if err != nil {
		t.Errorf("want err=nil got err=%v", err)
	}

}
