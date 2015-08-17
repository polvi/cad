package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	pb "github.com/polvi/cad/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"io/ioutil"
	"net"
)

var (
	trustedServerCAFile = flag.String("trusted-server-ca", "server-ca.crt", "The CA that signs trusted servers")
	certFile            = flag.String("cert", "my.crt", "This clients cert")
	keyFile             = flag.String("key", "my.key.insecure", "This clients key")
	serverAddr          = flag.String("server-addr", "localhost:10000", "The CAd server to connect to")

	getCA       = flag.Bool("get-ca", false, "Show the CA cert")
	signKeyFile = flag.String("sign-key", "", "Key that needs to be signed")
	hostname    = flag.String("hostname", "", "Hostname encoded in the cert, required for server certs")
)

func main() {
	flag.Parse()
	var opts []grpc.DialOption
	host, _, err := net.SplitHostPort(*serverAddr)
	if err != nil {
		grpclog.Fatalf("Failed parsing server addr", err)
	}
	creds, err := NewClientMutualTLSFromFile(*trustedServerCAFile, host, *certFile, *keyFile)
	if err != nil {
		grpclog.Fatalf("Failed to create TLS credentials %v", err)
	}
	opts = append(opts, grpc.WithTransportCredentials(creds))
	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		grpclog.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewCaClient(conn)
	if *getCA {
		caCert, err := client.GetCaCert(context.Background(), &pb.GetCaCertParams{})
		if err != nil {
			grpclog.Fatalf("%v.GetCaCert(_) = _, %v: ", client, err)
		}
		fmt.Printf("%s", caCert.Cert)
	}
	if *signKeyFile != "" {
		keyFile, err := ioutil.ReadFile(*signKeyFile)
		if err != nil {
			grpclog.Fatal(err)
		}
		key, err := NewKeyFromPrivateKeyPEM(keyFile)
		if err != nil {
			grpclog.Fatal(err)
		}
		csrPkixName := pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"cactl"},
			OrganizationalUnit: nil,
			Locality:           nil,
			Province:           nil,
			StreetAddress:      nil,
			PostalCode:         nil,
			SerialNumber:       "",
			CommonName:         *hostname,
		}

		csrTemplate := &x509.CertificateRequest{
			Subject:     csrPkixName,
			IPAddresses: []net.IP{},
			DNSNames:    []string{*hostname},
		}
		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key.Private)
		if err != nil {
			grpclog.Fatal(err)
			return
		}
		pemBlock := &pem.Block{
			Type:    "CERTIFICATE REQUEST",
			Headers: nil,
			Bytes:   csrBytes,
		}

		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, pemBlock); err != nil {
			grpclog.Fatal(err)
			return
		}
		signParams := &pb.SignParams{
			CSR: string(buf.Bytes()),
		}
		signed, err := client.Sign(context.Background(), signParams)
		if err != nil {
			grpclog.Fatalf("%v.GetCaCert(_) = _, %v: ", client, err)
		}
		fmt.Print(signed.Cert)
	}
}
func NewClientMutualTLSFromFile(trustedServerCAFile, serverName, certFile, keyFile string) (credentials.TransportAuthenticator, error) {
	b, err := ioutil.ReadFile(trustedServerCAFile)
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("credentials: failed to append certificates")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		ServerName:   serverName,
		RootCAs:      cp,
		Certificates: []tls.Certificate{cert},
	}
	return credentials.NewTLS(cfg), nil
}

type Key struct {
	Public  crypto.PublicKey
	Private crypto.PrivateKey
	// TODO(yichengq): add pemEncryptedBlock *pem.Block
}

func NewKey(pub crypto.PublicKey, priv crypto.PrivateKey) *Key {
	return &Key{Public: pub, Private: priv}
}

// NewKeyFromPrivateKeyPEM inits Key from PEM-format rsa private key bytes
func NewKeyFromPrivateKeyPEM(data []byte) (*Key, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != "RSA PRIVATE KEY" || len(pemBlock.Headers) != 0 {
		return nil, errors.New("unmatched type or headers")
	}

	priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return NewKey(&priv.PublicKey, priv), nil
}
