package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/cloudflare/cfssl/initca"
	pb "github.com/polvi/cad/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"math/big"
	"net"
	"time"

	"google.golang.org/grpc/grpclog"
)

var (
	trustedClientCAFile = flag.String("trusted-client-ca", "client-ca.crt", "The CA cert that signs trusted clients")
	certFile            = flag.String("cert", "127.0.0.10.crt", "This servers TLS cert")
	keyFile             = flag.String("key", "127.0.0.10.key.insecure", "This servers TLS key")

	caCertFile = flag.String("ca-cert", "ca.crt", "The public ca.crt for this CA")
	caKeyFile  = flag.String("ca-key", "ca.key.insecure", "The private key for this CA")
	serverAddr = flag.String("server-addr", "127.0.0.1:10000", "The server address in the format of host:port")
)

type caServer struct {
}

func (s *caServer) Sign(ctx context.Context, in *pb.SignParams) (*pb.SignedCert, error) {
	// serial is max 20 bytes
	serial, err := rand.Int(rand.Reader, big.NewInt(2^(20*8)))
	if err != nil {
		return nil, err
	}
	hostTemplate := x509.Certificate{
		// **SHOULD** be filled in a unique number
		SerialNumber: serial,
		// **SHOULD** be filled in host info
		Subject: pkix.Name{},
		// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
		NotBefore: time.Now().Add(-600).UTC(),
		// 10-year lease
		NotAfter: time.Time{},
		// Used for certificate signing only
		KeyUsage: 0,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		UnknownExtKeyUsage: nil,

		// activate CA
		BasicConstraintsValid: false,

		// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
		// (excluding the tag, length, and number of unused bits)
		// **SHOULD** be filled in later
		SubjectKeyId: nil,

		// Subject Alternative Name
		DNSNames: nil,

		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}
	// turn in.CSR to *x509.CertificateRequest
	block, _ := pem.Decode([]byte(in.CSR))

	rawCsr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	hostTemplate.Subject = rawCsr.Subject
	// TODO: 10 fixed years
	hostTemplate.NotAfter = time.Now().AddDate(10, 0, 0).UTC()

	// GenerateSubjectKeyId
	var pubBytes []byte
	pub := rawCsr.PublicKey
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only RSA public key is supported")
	}

	hash := sha1.Sum(pubBytes)
	hostTemplate.SubjectKeyId = hash[:]
	hostTemplate.IPAddresses = rawCsr.IPAddresses
	hostTemplate.DNSNames = rawCsr.DNSNames

	// load CA cert
	caCertPem, err := ioutil.ReadFile(*caCertFile)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(caCertPem)
	crts, err := x509.ParseCertificates(pemBlock.Bytes)
	if len(crts) != 1 {
		return nil, fmt.Errorf("unsupported multiple certificates in a block")
	}

	// load private key
	caCertPair, err := tls.LoadX509KeyPair(*caCertFile, *caKeyFile)
	if err != nil {
		return nil, err
	}
	signedCertBytes, err := x509.CreateCertificate(rand.Reader, &hostTemplate, crts[0], rawCsr.PublicKey, caCertPair.PrivateKey)
	if err != nil {
		return nil, err
	}
	pemBlock = &pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   signedCertBytes,
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, pemBlock); err != nil {
		return nil, err
	}
	return &pb.SignedCert{Cert: string(buf.Bytes())}, nil
}

type rsaPublicKey struct {
	N *big.Int
	E int
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", *serverAddr)
	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	creds, err := NewServerMutualTLSFromFile(*certFile, *keyFile, *trustedClientCAFile)
	if err != nil {

		grpclog.Fatalf("Failed to generate credentials %v", err)
	}
	opts = []grpc.ServerOption{grpc.Creds(creds)}
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterCaServer(grpcServer, &caServer{})
	grpcServer.Serve(lis)
}

func NewServerMutualTLSFromFile(certFile, keyFile, trustedClientCAFile string) (credentials.TransportAuthenticator, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caCert, err := ioutil.ReadFile(trustedClientCAFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cfg := &tls.Config{
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
	}
	return credentials.NewTLS(cfg), nil
}
