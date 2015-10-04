package kube

import (
	"bytes"
	"github.com/polvi/cad/x509ez"
	"github.com/polvi/procio/pkg/kubeapp/utils"
	"time"
)

func CreateMinSelfSignedCACertificateSecret(name string, expiry time.Duration) ([]byte, error) {
	cert, priv, err := x509ez.CreateMinSelfSignedCACertificate(expiry)
	if err != nil {
		return nil, err
	}
	s := &utils.BasicSecret{}
	var k, c bytes.Buffer

	if err := x509ez.CertToPem(cert, &c); err != nil {
		return nil, err
	}
	if err := x509ez.KeyToPem(priv, &k); err != nil {
		return nil, err
	}
	obj, err := s.Generate(map[string]interface{}{
		"name": name,
		"key":  k.Bytes(),
		"cert": c.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	objBytes, err := utils.EncodeObject(obj)
	if err != nil {
		return nil, err
	}

	return objBytes, nil
}
