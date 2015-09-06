package client

import (
	"crypto/x509"
	pb "github.com/polvi/cad/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type CaClient struct {
	grpcClient pb.CaClient
	parentCert *x509.Certificate
}

func (c *CaClient) ParentCert() (*x509.Certificate, error) {
	if c.parentCert != nil {
		return c.parentCert, nil
	}

	certResp, err := c.grpcClient.GetCaCert(context.Background(), &pb.GetCaCertParams{})
	if err != nil {
		return nil, err
	}
	parent, err := x509.ParseCertificate(certResp.Cert)
	if err != nil {
		return nil, err
	}
	c.parentCert = parent
	return c.parentCert, nil
}

func (c *CaClient) SignCa(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	signResp, err := c.grpcClient.SignCaCert(context.Background(), &pb.SignParams{
		CSR: csr.Raw,
	})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signResp.Cert)
}

func NewCaClient(addr string, tls bool, serverHostOverride string, trustedCaFile string) (*CaClient, error) {
	var opts []grpc.DialOption
	if tls {
		var sn string
		if serverHostOverride != "" {
			sn = serverHostOverride
		}
		var creds credentials.TransportAuthenticator
		if trustedCaFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(trustedCaFile, sn)
			if err != nil {
				return nil, err
			}
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return &CaClient{
		grpcClient: pb.NewCaClient(conn),
	}, nil
}
