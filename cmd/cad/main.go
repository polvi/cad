package main

import (
	"flag"
	"net"
	"time"

	"github.com/coreos/go-oidc/jose"
	pb "github.com/polvi/cad/proto"
	"github.com/polvi/cad/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
)

var (
	selfSigned         = flag.Bool("self-signed", false, "Have this CA generate a key and a self signed cert in memory")
	parentAddr         = flag.String("parent-addr", "", "Generate a private key, then have it signed by this parent CA")
	defaultDuration    = flag.String("default-duration", "1h", "If a duration is not requested, use this")
	maxDuration        = flag.String("max-duration", "1h", "Max duration of a cert allowed by this server")
	minDuration        = flag.String("min-duration", "1m", "Min duration of a cert allowed by this server")
	selfSignedDuration = flag.String("self-signed-duration", "1h", "Duration the self signed certificate if valid")

	tls        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	parentTls  = flag.Bool("parent-tls", false, "Connection uses TLS if true, else plain TCP")
	certFile   = flag.String("cert", "my.crt", "This servers TLS cert")
	keyFile    = flag.String("key", "my.key", "This servers TLS key")
	serverAddr = flag.String("server-addr", "127.0.0.1:10001", "The server address in the format of host:port")
)

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", *serverAddr)
	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			grpclog.Fatalf("Failed to generate credentials %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(opts...)
	c := &server.CaServer{}
	if !*selfSigned && *parentAddr == "" {
		grpclog.Fatalln("Must specify -self-signed or -parent-addr")
	}
	if *selfSigned {
		dur, err := time.ParseDuration(*selfSignedDuration)
		if err != nil {
			grpclog.Fatalln(err)
		}
		def, err := time.ParseDuration(*defaultDuration)
		if err != nil {
			grpclog.Fatalln(err)
		}
		max, err := time.ParseDuration(*maxDuration)
		if err != nil {
			grpclog.Fatalln(err)
		}
		min, err := time.ParseDuration(*minDuration)
		if err != nil {
			grpclog.Fatalln(err)
		}

		c, err = server.NewSelfSignedCaServer(dur, def, min, max)
		if err != nil {
			grpclog.Fatalf("unable to generate self signed ca: %s", err)
		}
		grpclog.Println("generated self-signed ca")
	}
	if *parentAddr != "" {
		c, err = server.NewCaServerFromParent(*parentAddr, jose.JWT{})
		if err != nil {
			grpclog.Fatalln("unable to create ca from parent:", err)
		}
		grpclog.Println("setup ca from parent", *parentAddr)
	}
	pb.RegisterCaServer(grpcServer, c)
	grpclog.Println("serving at", *serverAddr)
	grpcServer.Serve(lis)
}
