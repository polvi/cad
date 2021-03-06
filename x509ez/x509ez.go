package x509ez

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/coreos/go-oidc/oidc"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"os"
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

func CreateMinSelfSignedCACertificate(expiry time.Duration) (*x509.Certificate, *rsa.PrivateKey, error) {

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

func CreateMinCertificateRequest() (*x509.CertificateRequest, *rsa.PrivateKey, error) {

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

func CertToPem(cert *x509.Certificate, out io.Writer) error {
	if err := pem.Encode(out, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}); err != nil {
		return err
	}
	return nil
}

func WriteCertToFile(cert *x509.Certificate, file string) error {
	certFile, err := os.Create(file)
	defer certFile.Close()
	if err != nil {
		return err
	}
	if err := CertToPem(cert, certFile); err != nil {
		return err
	}
	return nil
}
func PemToCerts(in io.Reader) ([]*x509.Certificate, error) {
	d, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(d)
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func KeyToPem(priv *rsa.PrivateKey, out io.Writer) error {
	derPriv := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(out, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derPriv,
	}); err != nil {
		return err
	}
	return nil
}

func PemToKey(in io.Reader) (*rsa.PrivateKey, error) {
	d, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(d)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func WriteKeyToFile(priv *rsa.PrivateKey, file string) error {
	privFile, err := os.Create(file)
	defer privFile.Close()
	if err != nil {
		return err
	}
	if err := KeyToPem(priv, privFile); err != nil {
		return err
	}
	return nil
}
