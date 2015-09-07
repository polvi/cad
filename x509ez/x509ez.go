package x509ez

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/coreos/go-oidc/oidc"
	"math"
	"math/big"
	"time"
)

const rsaKeySize = 2048

func getMinimalCATemplate(expiry time.Duration) (*x509.Certificate, error) {
	tmpl, err := getMinimalTemplate(expiry)
	if err != nil {
		return nil, err
	}

	tmpl.IsCA = true

	return tmpl, nil

}

func getMinimalTemplate(expiry time.Duration) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{}

	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial

	now := time.Now()
	tmpl.NotBefore = now.Add(-5 * time.Minute).UTC()
	tmpl.NotAfter = now.Add(expiry).UTC()

	return tmpl, nil
}

func CreateMinSelfSignedCACertificate(expiry time.Duration) (*x509.Certificate, crypto.PrivateKey, error) {

	tmpl, err := getMinimalCATemplate(expiry)
	if err != nil {
		return nil, nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func CreateMinCertificateRequest() (*x509.CertificateRequest, crypto.PrivateKey, error) {

	tmpl := &x509.CertificateRequest{}

	priv, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return csr, priv, nil
}

func CreateCACertificate(expiry time.Duration, csr *x509.CertificateRequest, parent *x509.Certificate, priv crypto.PrivateKey) (*x509.Certificate, error) {

	tmpl, err := getMinimalCATemplate(expiry)
	if err != nil {
		return nil, err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, parent, csr.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

func CreateCertificate(expiry time.Duration, csr *x509.CertificateRequest, parent *x509.Certificate, priv crypto.PrivateKey) (*x509.Certificate, error) {
	tmpl, err := getMinimalTemplate(expiry)
	if err != nil {
		return nil, err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, parent, csr.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

func CreateCertificateFromIdentity(id *oidc.Identity, csr *x509.CertificateRequest, parent *x509.Certificate, priv crypto.PrivateKey) (*x509.Certificate, error) {
	tmpl, err := getMinimalTemplate(id.ExpiresAt.Sub(time.Now()))
	if err != nil {
		return nil, err
	}
	tmpl.Subject = pkix.Name{
		CommonName: id.ID,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, parent, csr.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}
