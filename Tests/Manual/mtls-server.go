// Local browser integration harness. Never exposes a listener beyond loopback.
// Usage: go run mtls-server.go /path/to/test-fixtures
// Fixtures: ca.pem, server.pem, server.key, client.pem.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: mtls-server FIXTURE_DIRECTORY")
	}
	directory := os.Args[1]
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			log.Fatal(err)
		}
		return data
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(read("ca.pem")) {
		log.Fatal("invalid test CA")
	}
	expected, _ := pem.Decode(read("client.pem"))
	if expected == nil {
		log.Fatal("invalid expected client certificate")
	}
	expectedHash := sha256.Sum256(expected.Bytes)
	serve := func(port int, version uint16, name string) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "Client certificate required", http.StatusUnauthorized)
				return
			}
			cert := r.TLS.PeerCertificates[0]
			actual := sha256.Sum256(cert.Raw)
			if actual != expectedHash {
				http.Error(w, "Unexpected client identity", http.StatusForbidden)
				return
			}
			result := map[string]string{"result": "mTLS authenticated", "tls": name,
				"subject": cert.Subject.String(), "client_certificate_sha256": hex.EncodeToString(actual[:])}
			encoded, _ := json.Marshal(result)
			log.Printf("VERIFIED %s", encoded)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			// All displayed values originate in this local fixture, not request input.
			fmt.Fprintf(w, "<!doctype html><title>SecureEnclaveToken mTLS validation</title><style>body{font:20px system-ui;max-width:800px;margin:80px auto;padding:30px}h1{color:#16834a}pre{font-size:15px;white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Client identity verified</h1><p>Chrome completed mutual TLS using the SecureEnclaveToken test identity.</p><pre>%s</pre>", html.EscapeString(string(encoded)))
		})
		server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: handler,
			TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: version, MaxVersion: version}}
		log.Printf("LISTEN https://localhost:%d (%s, client certificate required)", port, name)
		log.Fatal(server.ListenAndServeTLS(filepath.Join(directory, "server.pem"), filepath.Join(directory, "server.key")))
	}
	go serve(18443, tls.VersionTLS12, "TLS 1.2")
	serve(18444, tls.VersionTLS13, "TLS 1.3")
}
