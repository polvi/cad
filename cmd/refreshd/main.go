package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
	"github.com/polvi/cad/client"
	"github.com/polvi/cad/x509ez"
	"github.com/polvi/procio/util"
)

var (
	exitOnRefresh    = flag.Bool("exit-on-refresh", true, "Instead of rewriting the cert files, exit. Useful for crashing a pod that needs new credentials")
	refreshTokenFile = flag.String("refresh-token-file", "", "Location of file containing refresh token")
	certOutFile      = flag.String("cert-out-file", "cert.pem", "Write signed cert here")
	keyOutFile       = flag.String("key-out-file", "key.pem", "Write private key here")

	clientID     = flag.String("client-id", "XXX", "client id")
	clientSecret = flag.String("client-secret", "secrete", "secret")
	discovery    = flag.String("discovery", "http://127.0.0.1:5556", "discovery url")
	redirectURL  = flag.String("redirect-url", "http://127.0.0.1:5555/callback", "Redirect URL for third leg of OIDC")
)

func getJWT(c *oidc.Client, listenAddr string) (*oauth2.Client, chan *oauth2.TokenResponse, error) {
	jwtChan := make(chan *oauth2.TokenResponse)
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, err
	}
	oac, err := c.OAuthClient()
	if err != nil {
		return nil, nil, err
	}
	f := func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			return
		}
		token, err := oac.RequestToken(oauth2.GrantTypeAuthCode, code)
		if err != nil {
			fmt.Fprintf(w, "error: %s", err)
			return
		}
		jwtChan <- &token
		fmt.Fprintf(w, "Success! You can now close this window and go back to the CLI")
		l.Close()
	}
	go http.Serve(l, http.HandlerFunc(f))
	return oac, jwtChan, err
}

func main() {
	flag.Parse()

	if *refreshTokenFile == "" {
		fmt.Println("Must set -refresh-token-file")
		return
	}
	oidcClient, err := util.GetOIDCClient(*clientID, *clientSecret, *discovery, *redirectURL)
	if err != nil {
		fmt.Println(err)
		return
	}
	var tok *oauth2.TokenResponse
	f, err := os.Open(*refreshTokenFile)
	defer f.Close()
	if err != nil {
		fmt.Println("error reading refresh token, fetching a new one and writing to", *refreshTokenFile)
		oac, jwtChan, err := getJWT(oidcClient, "localhost:5555")
		if err != nil {
			fmt.Println(err)
			return
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(oac.AuthCodeURL("", "", ""))
		tok = <-jwtChan
		f, err := os.Create(*refreshTokenFile)
		defer f.Close()
		if err != nil {
			fmt.Println(err)
			return
		}
		f.Write([]byte(tok.RefreshToken))
	}
	refToken, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	jwt, err := oidcClient.RefreshToken(string(refToken))
	if err != nil {
		fmt.Println(err)
		return
	}
	c, err := client.NewCaClient("127.0.0.1:10001", jwt, false, "", "")
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
	certFile, err := os.Create(*certOutFile)
	defer certFile.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}); err != nil {
		fmt.Println(err)
		return
	}
	privFile, err := os.Create(*keyOutFile)
	defer privFile.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
	derPriv := x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
	if err := pem.Encode(privFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derPriv,
	}); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("wrote keys, sleeping until", cert.NotAfter)
	time.Sleep(cert.NotAfter.Sub(time.Now()))
}
