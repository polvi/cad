package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/polvi/cad/x509ez"
	"github.com/polvi/cad/x509ez/kube"
)

var (
	secretName         = flag.String("secret-name", "", "Name of the Secret object that generated")
	caCertFile         = flag.String("ca-cert", "", "Outfile for cert")
	caKeyFile          = flag.String("ca-key", "", "Outfile for key")
	selfSignedDuration = flag.String("self-signed-duration", "876000h", "(Duration the self signed certificate if valid (100 years by default)")
)

func main() {
	flag.Parse()
	if *secretName == "" && (*caCertFile == "" || *caKeyFile == "") {
		fmt.Println("must specify -secret-name or -ca-cert/key")
		return
	}
	dur, err := time.ParseDuration(*selfSignedDuration)
	if err != nil {
		fmt.Println(err)
		return
	}
	if *secretName != "" {
		objBytes, err := kube.CreateMinSelfSignedCACertificateSecret(*secretName, dur)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Print(string(objBytes))
	}
	if *caCertFile != "" && *caKeyFile != "" {
		cert, priv, err := x509ez.CreateMinSelfSignedCACertificate(dur)
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := x509ez.WriteKeyToFile(priv, *caKeyFile); err != nil {
			fmt.Println(err)
			return
		}
		if err := x509ez.WriteCertToFile(cert, *caCertFile); err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("wrote keys to", *caCertFile, *caKeyFile)
	}
}
