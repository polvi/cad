package server

import (
	"crypto"
	"crypto/x509"
	"github.com/polvi/cad/client"
	"github.com/polvi/x509ez"
	"time"

	pb "github.com/polvi/cad/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc/grpclog"
)

type CaServer struct {
	priv          crypto.PrivateKey
	cert          *x509.Certificate
	parent        *x509.Certificate
	client        *client.CaClient
	maxExpiry     time.Duration
	defaultExpiry time.Duration
}

func NewSelfSignedCaServer(expiry time.Duration, defaultExpiry time.Duration, maxExpiry time.Duration) (*CaServer, error) {
	cert, priv, err := x509ez.CreateMinSelfSignedCACertificate(expiry)
	if err != nil {
		return nil, err
	}
	return &CaServer{
		priv:          priv,
		cert:          cert,
		parent:        cert,
		defaultExpiry: defaultExpiry,
		maxExpiry:     maxExpiry,
	}, nil
}

func NewCaServerFromParent(parentAddr string) (*CaServer, error) {
	c, err := client.NewCaClient(parentAddr, false, "", "")
	if err != nil {
		return nil, err
	}
	csr, priv, err := x509ez.CreateMinCACertificateRequest()
	if err != nil {
		return nil, err
	}
	signedCert, err := c.SignCa(csr)
	if err != nil {
		return nil, err
	}
	parentCert, err := c.ParentCert()
	if err != nil {
		return nil, err
	}
	return &CaServer{
		cert:   signedCert,
		priv:   priv,
		client: c,
		parent: parentCert,
	}, nil
}

func (s *CaServer) GetCaCert(ctx context.Context, in *pb.GetCaCertParams) (*pb.CaCert, error) {
	grpclog.Printf("GetCaCert serial=%d\n", s.parent.SerialNumber)
	return &pb.CaCert{s.parent.Raw}, nil
}

func (s *CaServer) SignCaCert(ctx context.Context, in *pb.SignParams) (*pb.SignedCert, error) {
	d, err := s.getDuration(in.Duration)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(in.CSR)
	if err != nil {
		return nil, err
	}
	cert, err := x509ez.CreateCACertificate(*d,
		csr,
		s.parent,
		s.priv)
	if err != nil {
		return nil, err
	}

	grpclog.Printf("SignCaCert serial=%d parent=%d expiration=%s\n",
		cert.SerialNumber, s.parent.SerialNumber, cert.NotAfter)
	return &pb.SignedCert{
		Cert: cert.Raw,
	}, nil
}

func (s *CaServer) SignCert(ctx context.Context, in *pb.SignParams) (*pb.SignedCert, error) {
	d, err := s.getDuration(in.Duration)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(in.CSR)
	if err != nil {
		return nil, err
	}
	cert, err := x509ez.CreateCertificate(*d,
		csr,
		s.parent,
		s.priv)
	if err != nil {
		return nil, err
	}
	grpclog.Printf("SignCert serial=%d parent=%d expiration=%s\n",
		cert.SerialNumber, s.parent.SerialNumber, cert.NotAfter)
	return &pb.SignedCert{
		Cert: cert.Raw,
	}, nil
}

func (s *CaServer) getDuration(dur string) (*time.Duration, error) {
	d, err := time.ParseDuration(dur)
	if err != nil {
		return nil, err
	}
	if d > s.maxExpiry {
		d = s.maxExpiry
	}
	return &d, nil
}