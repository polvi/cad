package server

import (
	"crypto"
	"crypto/x509"
	"github.com/polvi/cad/client"
	"github.com/polvi/cad/x509ez"
	"time"

	"github.com/coreos/go-oidc/oidc"
	pb "github.com/polvi/cad/proto"
	grpcoidc "github.com/polvi/grpc-credentials/oidc"
	"golang.org/x/net/context"
	"google.golang.org/grpc/grpclog"
)

type CaServer struct {
	priv          crypto.PrivateKey
	cert          *x509.Certificate
	parent        *x509.Certificate
	client        *client.CaClient
	oidcClient    *oidc.Client
	maxExpiry     time.Duration
	minExpiry     time.Duration
	defaultExpiry time.Duration
}

func NewSelfSignedCaServer(oidcClient *oidc.Client, expiry time.Duration, defaultExpiry time.Duration, minExpiry, maxExpiry time.Duration) (*CaServer, error) {
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
		oidcClient:    oidcClient,
	}, nil
}

func NewCaServerFromParent(parentAddr string, refreshToken string, oidcClient *oidc.Client) (*CaServer, error) {
	idToken, err := oidcClient.RefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}
	c, err := client.NewCaClient(parentAddr, idToken, false, "", "")
	if err != nil {
		return nil, err
	}
	csr, priv, err := x509ez.CreateMinCertificateRequest()
	if err != nil {
		return nil, err
	}
	signedCert, err := c.SignCa(csr, time.Duration(1*time.Hour))
	if err != nil {
		return nil, err
	}
	parentCert, err := c.ParentCert()
	if err != nil {
		return nil, err
	}
	return &CaServer{
		cert:       signedCert,
		priv:       priv,
		client:     c,
		parent:     parentCert,
		oidcClient: oidcClient,
	}, nil
}

func (s *CaServer) GetCaCert(ctx context.Context, in *pb.GetCaCertParams) (*pb.CaCert, error) {
	grpclog.Printf("GetCaCert serial=%d\n", s.parent.SerialNumber)
	return &pb.CaCert{s.parent.Raw}, nil
}

func (s *CaServer) SignCaCert(ctx context.Context, in *pb.SignParams) (*pb.SignedCert, error) {
	d, err := s.getDuration(in.DurationSeconds)
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

	id, err := grpcoidc.VerifiedIdentityFromContext(s.oidcClient, ctx)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(in.CSR)
	if err != nil {
		return nil, err
	}
	cert, err := x509ez.CreateCertificateFromIdentity(id,
		csr,
		s.parent,
		s.priv)
	if err != nil {
		return nil, err
	}
	grpclog.Printf("SignCert cert.SerialNumber=%d parent.SerialNumber=%d cert.NotAfter=%q id.ID=%q id.Name=%q id.Email=%q id.ExpiresAt=%q\n",
		cert.SerialNumber, s.parent.SerialNumber, cert.NotAfter, id.ID, id.Name, id.Email, id.ExpiresAt)
	return &pb.SignedCert{
		Cert: cert.Raw,
	}, nil
}

func (s *CaServer) getDuration(seconds int64) (*time.Duration, error) {
	d := time.Duration(seconds) * time.Second
	if d > s.maxExpiry {
		d = s.maxExpiry
	}
	if d < s.minExpiry {
		d = s.minExpiry
	}
	return &d, nil
}
