// scoring-service-go combines Coraza/CRS's anomaly score and CrowdSec's
// decision into one composite score, served to Envoy as an ext_authz gRPC
// AuthorizationServer (see authz/) — the Go rewrite of the original
// Python/FastAPI scoring-service, now that Envoy's ext_authz filter runs
// in gRPC mode instead of HTTP mode.
package main

import (
	"log"
	"net"
	"net/http"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"

	"scoring-service-go/authz"
	"scoring-service-go/coraza"
	"scoring-service-go/crowdsec"
	"scoring-service-go/health"
)

const (
	grpcAddr = ":9001"
	httpAddr = ":8001"
)

func main() {
	// Background loops — same lifetime as the process, never crash it on
	// their own failure, just keep retrying (see their own doc comments).
	go coraza.PollHealth()
	go crowdsec.PollDecisionsStream()

	errCh := make(chan error, 2)

	go func() {
		lis, err := net.Listen("tcp", grpcAddr)
		if err != nil {
			errCh <- err
			return
		}
		// Plain grpc.NewServer with no TLS credentials serves h2c
		// (cleartext HTTP/2) — correct for this internal, unencrypted
		// Envoy<->scoring-service hop, same trust boundary as the plain
		// TCP HTTP setup this replaces.
		grpcServer := grpc.NewServer()
		authv3.RegisterAuthorizationServer(grpcServer, &authz.Server{})
		log.Printf("scoring-service-go: ext_authz gRPC listening on %s", grpcAddr)
		errCh <- grpcServer.Serve(lis)
	}()

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", health.Handler)
		log.Printf("scoring-service-go: HTTP /health listening on %s", httpAddr)
		errCh <- http.ListenAndServe(httpAddr, mux)
	}()

	// A crash in either server brings the container down cleanly (the
	// orchestrator restarts it) rather than limping half-alive.
	log.Fatal(<-errCh)
}
