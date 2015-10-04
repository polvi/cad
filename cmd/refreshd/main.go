package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/polvi/cad/client"
	"github.com/polvi/cad/x509ez"
)

var (
	exitOnRefresh = flag.Bool("exit-on-refresh", true, "Instead of rewriting the cert files, exit. Useful for crashing a pod that needs new credentials")
	certOutFile   = flag.String("cert-out-file", "cert.pem", "Write signed cert here")
	keyOutFile    = flag.String("key-out-file", "key.pem", "Write private key here")
	cadAddr       = flag.String("cad-addr", "localhost:10002", "Use this CAd server")
)

func main() {
	flag.Parse()

	c, err := client.NewCaClient(*cadAddr, false, "", "")
	if err != nil {
		fmt.Println(err)
		return
	}
	csr, priv, err := x509ez.CreateMinCertificateRequest()
	if err != nil {
		fmt.Println(err)
		return
	}
	cert, err := c.SignCert(csr, time.Duration(10*time.Second))
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := x509ez.WriteCertToFile(cert, *certOutFile); err != nil {
		fmt.Println(err)
		return
	}
	if err := x509ez.WriteKeyToFile(priv, *keyOutFile); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("wrote keys, sleeping until", cert.NotAfter)
	time.Sleep(cert.NotAfter.Sub(time.Now()))
}
