package x509ez

import (
	"testing"
	"time"
)

func TestCreateMinSelfSignedCACertificate(t *testing.T) {
	_, _, err := CreateMinSelfSignedCACertificate(time.Duration(5 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
}
func TestCreateMinCACertificateRequest(t *testing.T) {
	_, _, err := CreateMinCACertificateRequest()
	if err != nil {
		t.Fatal(err)
	}
}
