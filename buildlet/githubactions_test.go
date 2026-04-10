// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildlet

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v74/github"
)

// fakeDispatchHandler returns an http.Handler that records dispatch calls
// and can be configured to return errors.
type fakeDispatchHandler struct {
	dispatchCalled atomic.Bool
	lastInputs     atomic.Value // map[string]any
	statusCode     int          // 0 means 204 (success)
}

func (h *fakeDispatchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.dispatchCalled.Store(true)
		var body struct {
			Inputs map[string]any `json:"inputs"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		h.lastInputs.Store(body.Inputs)
	}
	code := h.statusCode
	if code == 0 {
		code = http.StatusNoContent
	}
	w.WriteHeader(code)
}

// newTestGHClient creates a GitHubActionsClient backed by a test HTTP server.
// The handler is called for all dispatch requests.
func newTestGHClient(t *testing.T, handler http.Handler) *GitHubActionsClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewGitHubActionsClient(srv.Client(), "test-token")
	c.client.apiBaseURL = srv.URL
	// Re-init clients map so the cached client picks up apiBaseURL.
	c.client.clients = make(map[int64]*github.Client)
	return c
}

// fakeBuildletWaiter is a test double for the BuildletWaiter interface.
type fakeBuildletWaiter struct {
	registered   map[string]time.Duration
	deregistered map[string]bool
	waitClient   Client
	waitErr      error
	waitCalled   bool
	lastWaitName string
}

func newFakeBuildletWaiter() *fakeBuildletWaiter {
	return &fakeBuildletWaiter{
		registered:   make(map[string]time.Duration),
		deregistered: make(map[string]bool),
	}
}

func (f *fakeBuildletWaiter) RegisterInstance(ctx context.Context, id string, wait time.Duration) {
	f.registered[id] = wait
}

func (f *fakeBuildletWaiter) WaitForInstance(ctx context.Context, id string) (Client, error) {
	f.waitCalled = true
	f.lastWaitName = id
	return f.waitClient, f.waitErr
}

func (f *fakeBuildletWaiter) DeregisterInstance(ctx context.Context, id string) {
	f.deregistered[id] = true
}

func TestGitHubActionsStartBuildlet(t *testing.T) {
	waiter := newFakeBuildletWaiter()
	waiter.waitClient = &FakeClient{}

	handler := &fakeDispatchHandler{}
	c := newTestGHClient(t, handler)

	dispatched := false
	opts := &GitHubActionsOpts{
		Repo:            "golang/build@main",
		WorkflowFile:    "test.yml",
		CoordinatorAddr: "localhost:443",
		Waiter:          waiter,
		OnWorkflowDispatched: func() {
			dispatched = true
		},
	}

	got, err := c.StartBuildlet(context.Background(), "inst-1", "host-test", opts)
	if err != nil {
		t.Fatalf("StartBuildlet: %v", err)
	}
	if got == nil {
		t.Fatal("StartBuildlet returned nil client")
	}
	if !handler.dispatchCalled.Load() {
		t.Error("DispatchWorkflow was not called")
	}
	if !waiter.waitCalled {
		t.Error("WaitForInstance was not called")
	}
	if waiter.lastWaitName != "inst-1" {
		t.Errorf("WaitForInstance called with %q, want %q", waiter.lastWaitName, "inst-1")
	}
	if _, ok := waiter.registered["inst-1"]; !ok {
		t.Error("RegisterInstance was not called for inst-1")
	}
	if !dispatched {
		t.Error("OnWorkflowDispatched hook was not called")
	}
	inputs, _ := handler.lastInputs.Load().(map[string]any)
	if inputs["instance_name"] != "inst-1" {
		t.Errorf("dispatch input instance_name = %q, want %q", inputs["instance_name"], "inst-1")
	}
	if inputs["host_type"] != "host-test" {
		t.Errorf("dispatch input host_type = %q, want %q", inputs["host_type"], "host-test")
	}
}

func TestGitHubActionsStartBuildletError(t *testing.T) {
	testCases := []struct {
		desc     string
		instName string
		hostType string
		opts     *GitHubActionsOpts
	}{
		{
			desc:     "nil-opts",
			instName: "inst-1",
			hostType: "host-test",
			opts:     nil,
		},
		{
			desc:     "nil-waiter",
			instName: "inst-1",
			hostType: "host-test",
			opts: &GitHubActionsOpts{
				Repo: "golang/build@main",
			},
		},
		{
			desc:     "empty-instName",
			instName: "",
			hostType: "host-test",
			opts: &GitHubActionsOpts{
				Waiter: newFakeBuildletWaiter(),
			},
		},
		{
			desc:     "empty-hostType",
			instName: "inst-1",
			hostType: "",
			opts: &GitHubActionsOpts{
				Waiter: newFakeBuildletWaiter(),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			c := newTestGHClient(t, &fakeDispatchHandler{})
			_, err := c.StartBuildlet(context.Background(), tc.instName, tc.hostType, tc.opts)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestGitHubActionsDispatchError(t *testing.T) {
	waiter := newFakeBuildletWaiter()
	handler := &fakeDispatchHandler{statusCode: http.StatusInternalServerError}
	c := newTestGHClient(t, handler)

	opts := &GitHubActionsOpts{
		Repo:         "golang/build@main",
		WorkflowFile: "test.yml",
		Waiter:       waiter,
	}

	_, err := c.StartBuildlet(context.Background(), "inst-1", "host-test", opts)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Instance should be deregistered on dispatch failure.
	if !waiter.deregistered["inst-1"] {
		t.Error("DeregisterInstance was not called after dispatch failure")
	}
}

func TestGitHubActionsWaitError(t *testing.T) {
	waiter := newFakeBuildletWaiter()
	waiter.waitErr = errors.New("connection timeout")

	handler := &fakeDispatchHandler{}
	c := newTestGHClient(t, handler)

	opts := &GitHubActionsOpts{
		Repo:         "golang/build@main",
		WorkflowFile: "test.yml",
		Waiter:       waiter,
	}

	_, err := c.StartBuildlet(context.Background(), "inst-1", "host-test", opts)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !handler.dispatchCalled.Load() {
		t.Error("DispatchWorkflow should have been called before the wait error")
	}
}

func TestGitHubActionsDefaultTimeout(t *testing.T) {
	waiter := newFakeBuildletWaiter()
	waiter.waitClient = &FakeClient{}

	c := newTestGHClient(t, &fakeDispatchHandler{})

	opts := &GitHubActionsOpts{
		Repo:         "golang/build@main",
		WorkflowFile: "test.yml",
		Waiter:       waiter,
	}

	_, err := c.StartBuildlet(context.Background(), "inst-1", "host-test", opts)
	if err != nil {
		t.Fatalf("StartBuildlet: %v", err)
	}
	if got := waiter.registered["inst-1"]; got != 30*time.Minute {
		t.Errorf("registration timeout = %v, want %v", got, 30*time.Minute)
	}
}

func TestGitHubActionsCustomTimeout(t *testing.T) {
	waiter := newFakeBuildletWaiter()
	waiter.waitClient = &FakeClient{}

	c := newTestGHClient(t, &fakeDispatchHandler{})

	opts := &GitHubActionsOpts{
		Repo:                "golang/build@main",
		WorkflowFile:        "test.yml",
		Waiter:              waiter,
		RegistrationTimeout: 10 * time.Minute,
	}

	_, err := c.StartBuildlet(context.Background(), "inst-1", "host-test", opts)
	if err != nil {
		t.Fatalf("StartBuildlet: %v", err)
	}
	if got := waiter.registered["inst-1"]; got != 10*time.Minute {
		t.Errorf("registration timeout = %v, want %v", got, 10*time.Minute)
	}
}

func testPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func TestNewGitHubActionsClientFromApp(t *testing.T) {
	keyPEM := testPrivateKeyPEM(t)
	client, err := NewGitHubActionsClientFromApp(http.DefaultClient, 12345, keyPEM)
	if err != nil {
		t.Fatalf("NewGitHubActionsClientFromApp: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewGitHubActionsClientFromAppInvalidKey(t *testing.T) {
	_, err := NewGitHubActionsClientFromApp(http.DefaultClient, 12345, []byte("not a pem key"))
	if err == nil {
		t.Fatal("expected error for invalid PEM key")
	}
}

func TestGhAppAPIClientCaching(t *testing.T) {
	keyPEM := testPrivateKeyPEM(t)
	var installRequests, tokenRequests atomic.Int32
	mux := http.NewServeMux()
	// go-github's WithEnterpriseURLs adds /api/v3/ prefix.
	mux.HandleFunc("/api/v3/repos/golang/build/installation", func(w http.ResponseWriter, r *http.Request) {
		installRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(github.Installation{ID: github.Ptr(int64(67890))})
	})
	mux.HandleFunc("/api/v3/repos/golang/infra/installation", func(w http.ResponseWriter, r *http.Request) {
		installRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(github.Installation{ID: github.Ptr(int64(67890))})
	})
	mux.HandleFunc("/api/v3/app/installations/67890/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		tokenRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     github.Ptr(fmt.Sprintf("ghs_token_%d", tokenRequests.Load())),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(time.Hour)},
		})
	})
	// Workflow dispatch endpoints (return 204 No Content).
	mux.HandleFunc("/api/v3/repos/golang/build/actions/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/v3/repos/golang/infra/actions/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	block, _ := pem.Decode(keyPEM)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	c := &ghAPIClient{
		httpClient: srv.Client(),
		clientID:   12345,
		privateKey: key,
		apiBaseURL: srv.URL,
		instIDs:    make(map[string]int64),
		clients:    make(map[int64]*github.Client),
	}

	// First call should resolve installation and fetch a token.
	if err := c.DispatchWorkflow(context.Background(), "golang", "build", "test.yml", "main", nil); err != nil {
		t.Fatalf("DispatchWorkflow: %v", err)
	}
	if installRequests.Load() != 1 {
		t.Fatalf("expected 1 install request, got %d", installRequests.Load())
	}
	if tokenRequests.Load() != 1 {
		t.Fatalf("expected 1 token request, got %d", tokenRequests.Load())
	}

	// Second call for same repo should reuse cached installation ID and token.
	if err := c.DispatchWorkflow(context.Background(), "golang", "build", "test.yml", "main", nil); err != nil {
		t.Fatalf("DispatchWorkflow: %v", err)
	}
	if installRequests.Load() != 1 {
		t.Fatalf("expected 1 install request (cached), got %d", installRequests.Load())
	}
	if tokenRequests.Load() != 1 {
		t.Fatalf("expected 1 token request (cached), got %d", tokenRequests.Load())
	}

	// Call for different repo with same installation ID should reuse token.
	if err := c.DispatchWorkflow(context.Background(), "golang", "infra", "test.yml", "main", nil); err != nil {
		t.Fatalf("DispatchWorkflow: %v", err)
	}
	if installRequests.Load() != 2 {
		t.Fatalf("expected 2 install requests, got %d", installRequests.Load())
	}
	if tokenRequests.Load() != 1 {
		t.Fatalf("expected 1 token request (same installation), got %d", tokenRequests.Load())
	}
}
