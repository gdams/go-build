// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mockcoordinator runs a minimal mock coordinator for
// end-to-end testing of the GitHub Actions buildlet workflow.
//
// It starts a TLS server that:
//   - Accepts webhook callbacks from the GHA runner at /github-actions/webhook
//   - Accepts reverse buildlet connections at /github-actions/reverse
//   - Optionally dispatches the workflow via the GitHub API
//
// Usage:
//
//	# 1. Start the mock coordinator:
//	go run ./cmd/mockcoordinator --webhook-secret=mysecret
//
//	# 2. In another terminal, expose it via a tunnel (e.g. ngrok):
//	ngrok http https://localhost:8443
//
//	# 3. Dispatch the workflow (use --dispatch with the tunnel URL):
//	go run ./cmd/mockcoordinator \
//	  --webhook-secret=mysecret \
//	  --dispatch \
//	  --github-token=ghp_... \
//	  --github-repo=gdams/go-build \
//	  --github-ref=gha-windows-arm64-buildlet \
//	  --coordinator-url=https://abc123.ngrok.io
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

var (
	addr          = flag.String("addr", ":8443", "TLS listen address")
	webhookSecret = flag.String("webhook-secret", "", "HMAC secret for webhook validation (required)")

	// Dispatch flags
	dispatch       = flag.Bool("dispatch", false, "dispatch a workflow run after starting the server")
	githubToken    = flag.String("github-token", "", "GitHub token for dispatching (or set GITHUB_TOKEN env)")
	githubRepo     = flag.String("github-repo", "gdams/go-build", "GitHub owner/repo")
	githubRef      = flag.String("github-ref", "gha-windows-arm64-buildlet", "Git ref (branch) to dispatch on")
	workflowFile   = flag.String("workflow", "win11-arm-buildlet.yml", "workflow filename to dispatch")
	coordinatorURL = flag.String("coordinator-url", "", "public URL of this mock coordinator (e.g., ngrok URL)")
	instanceName   = flag.String("instance-name", "", "instance name to pass to workflow (auto-generated if empty)")
)

func main() {
	flag.Parse()

	if *webhookSecret == "" {
		log.Fatal("--webhook-secret is required")
	}

	if *githubToken == "" {
		*githubToken = os.Getenv("GITHUB_TOKEN")
	}

	if *instanceName == "" {
		*instanceName = fmt.Sprintf("test-buildlet-win11-arm64-%d", time.Now().Unix())
	}

	mc := &mockCoordinator{
		webhookSecret: *webhookSecret,
		events:        make(chan event, 100),
	}

	// Generate self-signed TLS certificate.
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate TLS cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/github-actions/webhook", mc.handleWebhook)
	mux.HandleFunc("/github-actions/reverse", mc.handleReverse)
	mux.HandleFunc("/reverse", mc.handleBuildletReverse)
	mux.HandleFunc("/revdial", mc.handleRevdial)
	mux.HandleFunc("/", mc.handleStatus)

	srv := &http.Server{
		Addr:    *addr,
		Handler: logMiddleware(mux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	// Start event printer.
	go mc.printEvents()

	// Start server.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *addr, err)
	}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)

	log.Printf("=== Mock Coordinator ===")
	log.Printf("Listening on https://localhost%s", *addr)
	log.Printf("Instance name: %s", *instanceName)
	log.Printf("Webhook secret: %s", *webhookSecret)
	log.Printf("")
	log.Printf("Endpoints:")
	log.Printf("  POST /github-actions/webhook  — webhook callback from GHA runner")
	log.Printf("  GET  /github-actions/reverse  — reverse buildlet connection")
	log.Printf("  GET  /                        — status page")
	log.Printf("")

	go func() {
		if err := srv.Serve(tlsLn); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Optionally dispatch the workflow.
	if *dispatch {
		if *githubToken == "" {
			log.Fatal("--github-token (or GITHUB_TOKEN env) required for --dispatch")
		}
		if *coordinatorURL == "" {
			log.Fatal("--coordinator-url required for --dispatch (e.g., your ngrok URL)")
		}
		go func() {
			// Give the server a moment to start.
			time.Sleep(500 * time.Millisecond)
			if err := dispatchWorkflow(); err != nil {
				log.Printf("ERROR dispatching workflow: %v", err)
			}
		}()
	} else {
		log.Printf("To dispatch manually, run:")
		log.Printf("  gh workflow run %s --repo %s --ref %s \\", *workflowFile, *githubRepo, *githubRef)
		log.Printf("    -f instance_name=%s \\", *instanceName)
		log.Printf("    -f host_type=host-windows11-arm64-gha \\")
		log.Printf("    -f coordinator=<YOUR_TUNNEL_HOST>:443")
	}

	log.Printf("")
	log.Printf("Waiting for events... (Ctrl+C to stop)")
	log.Printf("")

	// Wait for interrupt.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh

	log.Printf("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

type event struct {
	Time    time.Time
	Type    string
	Message string
}

type mockCoordinator struct {
	webhookSecret string
	events        chan event

	mu             sync.Mutex
	webhookCalled  bool
	webhookPayload map[string]interface{}
	buildletConn   bool
}

func (mc *mockCoordinator) emit(typ, msg string) {
	mc.events <- event{Time: time.Now(), Type: typ, Message: msg}
}

func (mc *mockCoordinator) printEvents() {
	for ev := range mc.events {
		log.Printf("[%s] %s: %s", ev.Time.Format("15:04:05"), ev.Type, ev.Message)
	}
}

func (mc *mockCoordinator) handleStatus(w http.ResponseWriter, r *http.Request) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h1>Mock Coordinator</h1>")
	fmt.Fprintf(w, "<p>Instance: <code>%s</code></p>", *instanceName)
	fmt.Fprintf(w, "<h2>Status</h2><ul>")
	fmt.Fprintf(w, "<li>Webhook received: %v</li>", mc.webhookCalled)
	fmt.Fprintf(w, "<li>Buildlet connected: %v</li>", mc.buildletConn)
	fmt.Fprintf(w, "</ul>")
	if mc.webhookPayload != nil {
		b, _ := json.MarshalIndent(mc.webhookPayload, "", "  ")
		fmt.Fprintf(w, "<h2>Webhook Payload</h2><pre>%s</pre>", b)
	}
}

func (mc *mockCoordinator) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		mc.emit("WEBHOOK", fmt.Sprintf("ERROR reading body: %v", err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Validate HMAC.
	sig := r.Header.Get("X-Hub-Signature-256")
	if !mc.validateHMAC(body, sig) {
		mc.emit("WEBHOOK", fmt.Sprintf("ERROR invalid signature: %s", sig))
		http.Error(w, "invalid signature", http.StatusForbidden)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		mc.emit("WEBHOOK", fmt.Sprintf("ERROR invalid JSON: %v", err))
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	mc.mu.Lock()
	mc.webhookCalled = true
	mc.webhookPayload = payload
	mc.mu.Unlock()

	mc.emit("WEBHOOK", fmt.Sprintf("SUCCESS — instance=%v run_id=%v status=%v",
		payload["instance_name"], payload["run_id"], payload["status"]))

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"ok":true}`)
}

func (mc *mockCoordinator) handleReverse(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Go-Gomote-ID")
	hostname := r.Header.Get("X-Go-Hostname")

	mc.emit("REVERSE", fmt.Sprintf("Connection attempt — id=%s hostname=%s remote=%s", id, hostname, r.RemoteAddr))

	mc.mu.Lock()
	mc.buildletConn = true
	mc.mu.Unlock()

	// For the mock, we just acknowledge the connection.
	// A real coordinator would hijack and set up revdial.
	mc.emit("REVERSE", fmt.Sprintf("SUCCESS — Buildlet connected! id=%s", id))

	// Respond with 101 Switching Protocols to simulate the real flow.
	hj, ok := w.(http.Hijacker)
	if !ok {
		mc.emit("REVERSE", "ERROR server doesn't support hijacking")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		mc.emit("REVERSE", fmt.Sprintf("ERROR hijack failed: %v", err))
		return
	}

	// Write the protocol switch response.
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Proto: "HTTP/1.1"}
	resp.Write(bufrw)
	bufrw.Flush()

	mc.emit("REVERSE", "Connection hijacked — buildlet is now connected via revdial")
	mc.emit("REVERSE", "Holding connection open (Ctrl+C to stop)...")

	// Keep the connection open until interrupted.
	// In a real coordinator, revdial would multiplex over this conn.
	buf := make([]byte, 1)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			mc.emit("REVERSE", fmt.Sprintf("Connection closed: %v", err))
			conn.Close()
			return
		}
	}
}

// handleBuildletReverse handles the standard /reverse endpoint that the
// buildlet binary connects to in reverse mode. It validates the dev builder
// key and responds with 101 Switching Protocols.
func (mc *mockCoordinator) handleBuildletReverse(w http.ResponseWriter, r *http.Request) {
	hostType := r.Header.Get("X-Go-Host-Type")
	builderKey := r.Header.Get("X-Go-Builder-Key")
	hostname := r.Header.Get("X-Go-Builder-Hostname")
	version := r.Header.Get("X-Go-Builder-Version")

	mc.emit("BUILDLET", fmt.Sprintf("Reverse connection — hostType=%s hostname=%s version=%s remote=%s",
		hostType, hostname, version, r.RemoteAddr))

	// Validate the dev builder key.
	expectedKey := devBuilderKey(hostType)
	if builderKey != expectedKey {
		mc.emit("BUILDLET", fmt.Sprintf("ERROR invalid key for %s (got %s, want %s)", hostType, builderKey, expectedKey))
		http.Error(w, "invalid builder key", http.StatusForbidden)
		return
	}
	mc.emit("BUILDLET", "Builder key validated OK")

	mc.mu.Lock()
	mc.buildletConn = true
	mc.mu.Unlock()

	// Hijack the connection and send 101 Switching Protocols.
	hj, ok := w.(http.Hijacker)
	if !ok {
		mc.emit("BUILDLET", "ERROR server doesn't support hijacking")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		mc.emit("BUILDLET", fmt.Sprintf("ERROR hijack failed: %v", err))
		return
	}

	// Write the 101 response the buildlet expects.
	fmt.Fprintf(bufrw, "HTTP/1.1 101 Switching Protocols\r\n\r\n")
	bufrw.Flush()

	mc.emit("BUILDLET", fmt.Sprintf("SUCCESS — Buildlet %s connected and protocol switched!", hostname))
	mc.emit("BUILDLET", "Connection is live — buildlet is ready to accept work")
	mc.emit("BUILDLET", "Holding connection open (Ctrl+C to stop)...")

	// Hold the connection open. In a real coordinator, revdial
	// would multiplex HTTP requests over this connection.
	buf := make([]byte, 256)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			mc.emit("BUILDLET", fmt.Sprintf("Connection ended: %v", err))
			conn.Close()
			return
		}
		if n > 0 {
			mc.emit("BUILDLET", fmt.Sprintf("Received %d bytes from buildlet", n))
		}
	}
}

// handleRevdial handles the /revdial endpoint used by revdial v2.
func (mc *mockCoordinator) handleRevdial(w http.ResponseWriter, r *http.Request) {
	mc.emit("REVDIAL", fmt.Sprintf("Revdial connection from %s", r.RemoteAddr))
	// For mock purposes, just hold the connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	mc.emit("REVDIAL", "Connection established")
	buf := make([]byte, 256)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return
		}
	}
}

// devBuilderKey generates the same dev key as the buildlet binary.
// Uses HMAC-MD5 with "gophers rule" as the master key.
const devMasterKey = "gophers rule"

func devBuilderKey(builder string) string {
	h := hmac.New(md5.New, []byte(devMasterKey))
	io.WriteString(h, builder)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (mc *mockCoordinator) validateHMAC(body []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(mc.webhookSecret))
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("HTTP %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func dispatchWorkflow() error {
	log.Printf("Dispatching workflow %s on %s/%s ...", *workflowFile, *githubRepo, *githubRef)

	// Parse the coordinator URL to get just the host for the workflow input.
	coordHost := strings.TrimPrefix(*coordinatorURL, "https://")
	coordHost = strings.TrimPrefix(coordHost, "http://")
	coordHost = strings.TrimSuffix(coordHost, "/")

	payload := map[string]interface{}{
		"ref": *githubRef,
		"inputs": map[string]string{
			"instance_name": *instanceName,
			"host_type":     "host-windows11-arm64-gha",
			"coordinator":   coordHost + ":443",
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/workflows/%s/dispatches",
		*githubRepo, *workflowFile)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+*githubToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		log.Printf("Workflow dispatched successfully!")
		log.Printf("Check: https://github.com/%s/actions/workflows/%s", *githubRepo, *workflowFile)
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("dispatch returned %d: %s", resp.StatusCode, string(respBody))
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Go Mock Coordinator"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
