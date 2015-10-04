package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/polvi/cad/x509ez/kube"
)

var (
	secretName         = flag.String("secret-name", "root-ca", "Name of the Secret object that generated")
	selfSignedDuration = flag.String("self-signed-duration", "876000h", "(Duration the self signed certificate if valid (100 years by default)")
)

func main() {
	flag.Parse()
	dur, err := time.ParseDuration(*selfSignedDuration)
	if err != nil {
		fmt.Println(err)

	}
	objBytes, err := kube.CreateMinSelfSignedCACertificateSecret(*secretName, dur)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(string(objBytes))
}
