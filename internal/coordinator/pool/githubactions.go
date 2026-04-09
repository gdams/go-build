// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || darwin

package pool

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/build/buildlet"
	"golang.org/x/build/dashboard"
	"golang.org/x/build/internal/coordinator/pool/queue"
	"golang.org/x/build/internal/rendezvous"
	"golang.org/x/build/internal/secret"
)

var _ Buildlet = (*GitHubActionsBuildlet)(nil)

// gitHubActionsBuildlet is the package level GitHub Actions buildlet pool.
var gitHubActionsBuildlet *GitHubActionsBuildlet

// GitHubActionsPool retrieves the package level GitHubActionsBuildlet pool.
func GitHubActionsPool() *GitHubActionsBuildlet {
	return gitHubActionsBuildlet
}

// GitHubActionsOpt is optional configuration for the GitHub Actions buildlet pool.
type GitHubActionsOpt func(*GitHubActionsBuildlet)

// GitHubActionsBuildlet manages a pool of buildlets backed by GitHub Actions runners.
// When a buildlet is requested, it triggers a GitHub Actions workflow_dispatch event
// that starts a Windows 11 ARM runner. The runner connects to LUCI, then executes
// golangbuild, and finally connects back as a reverse buildlet via the rendezvous system.
type GitHubActionsBuildlet struct {
	// httpClient is used to make GitHub API calls.
	httpClient *http.Client
	// ghToken is the GitHub personal access token for triggering workflow dispatches.
	ghToken string
	// webhookSecret is the HMAC secret for validating incoming webhook callbacks.
	webhookSecret string
	// owner is the GitHub repository owner (e.g., "golang").
	owner string
	// repo is the GitHub repository name (e.g., "build").
	repo string
	// workflowFile is the workflow filename to dispatch (e.g., "win11-arm-buildlet.yml").
	workflowFile string
	// gitRef is the git ref (branch) to dispatch the workflow on.
	gitRef string
	// coordinatorAddr is the address the workflow runner should connect back to.
	coordinatorAddr string
	// hosts provides the host configuration for all hosts.
	hosts map[string]*dashboard.HostConfig
	// rendezvous coordinates buildlet connections.
	rendezvous *rendezvous.Rendezvous

	mu       sync.Mutex
	active   map[string]*ghaInstance // keyed by instance name
	startSeq int64                   // monotonic counter for instance names
}

// ghaInstance tracks a single GitHub Actions-backed buildlet instance.
type ghaInstance struct {
	Name      string
	HostType  string
	Created   time.Time
	RunID     int64  // GitHub Actions run ID, populated after dispatch
	Status    string // "dispatching", "running", "connected", "done"
	WorkflowS string // workflow file that was dispatched
}

// NewGitHubActionsBuildlet creates a new GitHub Actions buildlet pool.
func NewGitHubActionsBuildlet(
	sc *secret.Client,
	hosts map[string]*dashboard.HostConfig,
	rdv *rendezvous.Rendezvous,
	opts ...GitHubActionsOpt,
) (*GitHubActionsBuildlet, error) {
	b := &GitHubActionsBuildlet{
		httpClient:      http.DefaultClient,
		hosts:           hosts,
		rendezvous:      rdv,
		active:          make(map[string]*ghaInstance),
		owner:           "golang",
		repo:            "build",
		workflowFile:    "win11-arm-buildlet.yml",
		gitRef:          "main",
		coordinatorAddr: "farmer.golang.org:443",
	}
	for _, opt := range opts {
		opt(b)
	}

	// In dev mode (no secret client), allow env var overrides.
	if sc == nil {
		if v := os.Getenv("GHA_GITHUB_TOKEN"); v != "" {
			b.ghToken = v
		}
		if v := os.Getenv("GHA_REPO_OWNER"); v != "" {
			b.owner = v
		}
		if v := os.Getenv("GHA_REPO_NAME"); v != "" {
			b.repo = v
		}
		if v := os.Getenv("GHA_GIT_REF"); v != "" {
			b.gitRef = v
		}
		if v := os.Getenv("GHA_COORDINATOR_ADDR"); v != "" {
			b.coordinatorAddr = v
		}
	}

	// Retrieve secrets if a secret client is available.
	if sc != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		token, err := sc.Retrieve(ctx, secret.NameGitHubActionsToken)
		if err != nil {
			return nil, fmt.Errorf("github actions pool: unable to retrieve GitHub token: %w", err)
		}
		b.ghToken = token
		whSecret, err := sc.Retrieve(ctx, secret.NameGitHubActionsWebhookSecret)
		if err != nil {
			return nil, fmt.Errorf("github actions pool: unable to retrieve webhook secret: %w", err)
		}
		b.webhookSecret = whSecret
	}

	gitHubActionsBuildlet = b
	return b, nil
}

// GetBuildlet triggers a GitHub Actions workflow to provision a Windows 11 ARM
// buildlet. The workflow connects to LUCI, runs golangbuild setup, and then
// connects back as a reverse buildlet through the rendezvous system.
func (b *GitHubActionsBuildlet) GetBuildlet(ctx context.Context, hostType string, lg Logger, si *queue.SchedItem) (buildlet.Client, error) {
	hconf, ok := b.hosts[hostType]
	if !ok {
		return nil, fmt.Errorf("github actions pool: unknown host type %q", hostType)
	}

	instName := b.newInstanceName(hostType)
	log.Printf("Creating GitHub Actions buildlet %q for %s", instName, hostType)

	dispatchSpan := lg.CreateSpan("dispatch_github_actions", instName)

	// Register with rendezvous before dispatching so the runner can connect back.
	b.rendezvous.RegisterInstance(ctx, instName, 30*time.Minute)

	// Track the instance.
	b.mu.Lock()
	b.active[instName] = &ghaInstance{
		Name:      instName,
		HostType:  hostType,
		Created:   time.Now(),
		Status:    "dispatching",
		WorkflowS: b.workflowFile,
	}
	b.mu.Unlock()

	// Dispatch the GitHub Actions workflow.
	if err := b.dispatchWorkflow(ctx, instName, hostType, hconf); err != nil {
		dispatchSpan.Done(err)
		b.rendezvous.DeregisterInstance(ctx, instName)
		b.removeInstance(instName)
		return nil, fmt.Errorf("github actions pool: dispatch failed for %s: %w", instName, err)
	}
	dispatchSpan.Done(nil)

	b.mu.Lock()
	if inst, ok := b.active[instName]; ok {
		inst.Status = "running"
	}
	b.mu.Unlock()

	log.Printf("GitHub Actions workflow dispatched for %s, waiting for buildlet connection", instName)

	// Wait for the runner to connect back via the rendezvous system.
	waitSpan := lg.CreateSpan("wait_github_actions_buildlet", instName)
	bc, err := b.rendezvous.WaitForInstance(ctx, instName)
	waitSpan.Done(err)
	if err != nil {
		b.removeInstance(instName)
		return nil, fmt.Errorf("github actions pool: buildlet connection failed for %s: %w", instName, err)
	}

	b.mu.Lock()
	if inst, ok := b.active[instName]; ok {
		inst.Status = "connected"
	}
	b.mu.Unlock()

	bc.SetDescription(fmt.Sprintf("GitHub Actions: %s", instName))
	bc.SetOnHeartbeatFailure(func() {
		log.Printf("GitHub Actions buildlet %q failed heartbeat", instName)
		b.buildletDone(instName)
	})
	bc.SetInstanceName(instName)
	return bc, nil
}

// dispatchWorkflow triggers a GitHub Actions workflow_dispatch event.
func (b *GitHubActionsBuildlet) dispatchWorkflow(ctx context.Context, instName, hostType string, hconf *dashboard.HostConfig) error {
	payload := map[string]interface{}{
		"ref": b.gitRef,
		"inputs": map[string]string{
			"instance_name": instName,
			"host_type":     hostType,
			"coordinator":   b.coordinatorAddr,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal dispatch payload: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/workflows/%s/dispatches",
		b.owner, b.repo, b.workflowFile)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create dispatch request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.ghToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("dispatch returned status %d: %s", resp.StatusCode, string(respBody))
	}
	log.Printf("GitHub Actions workflow dispatched for %s (status %d)", instName, resp.StatusCode)
	return nil
}

// HandleWebhook handles incoming webhook callbacks from GitHub Actions runners.
// The runner calls this endpoint after connecting to LUCI and before starting golangbuild,
// to confirm it is alive and provide its run ID.
//
// Expected JSON body:
//
//	{
//	  "instance_name": "buildlet-windows11-arm64-gha-rn...",
//	  "run_id": 12345,
//	  "status": "ready"
//	}
func (b *GitHubActionsBuildlet) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Validate HMAC signature from the X-Hub-Signature-256 header.
	if b.webhookSecret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !b.validateHMAC(bodyBytes, sig) {
			http.Error(w, "invalid signature", http.StatusForbidden)
			return
		}
	}

	var payload struct {
		InstanceName string `json:"instance_name"`
		RunID        int64  `json:"run_id"`
		Status       string `json:"status"`
	}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if payload.InstanceName == "" {
		http.Error(w, "missing instance_name", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	inst, ok := b.active[payload.InstanceName]
	if !ok {
		// In dev mode (no webhook secret configured), auto-register
		// unknown instances so the e2e flow can be tested without
		// a prior GetBuildlet call.
		if b.webhookSecret == "" {
			inst = &ghaInstance{
				Name:    payload.InstanceName,
				Created: time.Now(),
				Status:  "webhook-registered",
			}
			b.active[payload.InstanceName] = inst
			ok = true
			log.Printf("GitHub Actions webhook: auto-registered instance=%s (dev mode)", payload.InstanceName)
		}
	}
	if ok && payload.RunID != 0 {
		inst.RunID = payload.RunID
	}
	b.mu.Unlock()

	if !ok {
		http.Error(w, "unknown instance", http.StatusNotFound)
		return
	}

	log.Printf("GitHub Actions webhook: instance=%s run_id=%d status=%s", payload.InstanceName, payload.RunID, payload.Status)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"ok":true}`)
}

// validateHMAC checks the X-Hub-Signature-256 header against the webhook secret.
func (b *GitHubActionsBuildlet) validateHMAC(body []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(b.webhookSecret))
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
}

// String gives a report of capacity usage for the GitHub Actions buildlet pool.
func (b *GitHubActionsBuildlet) String() string {
	b.mu.Lock()
	n := len(b.active)
	b.mu.Unlock()
	return fmt.Sprintf("GitHub Actions pool: %d active instances", n)
}

// WriteHTMLStatus writes the status of the GitHub Actions buildlet pool to an io.Writer.
func (b *GitHubActionsBuildlet) WriteHTMLStatus(w io.Writer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fmt.Fprintf(w, "<b>GitHub Actions pool</b>: %d active instances", len(b.active))

	if len(b.active) > 0 {
		fmt.Fprintf(w, "<ul>")
		for _, inst := range b.active {
			fmt.Fprintf(w, "<li>%s (%s) — %s, %s</li>\n",
				html.EscapeString(inst.Name),
				html.EscapeString(inst.HostType),
				html.EscapeString(inst.Status),
				friendlyDuration(time.Since(inst.Created)),
			)
		}
		fmt.Fprintf(w, "</ul>")
	}
}

// buildletDone marks an instance as done and removes it from tracking.
func (b *GitHubActionsBuildlet) buildletDone(instName string) {
	b.removeInstance(instName)
}

// removeInstance removes an instance from the active tracking map.
func (b *GitHubActionsBuildlet) removeInstance(instName string) {
	b.mu.Lock()
	delete(b.active, instName)
	b.mu.Unlock()
}

// newInstanceName generates a unique instance name for the given host type.
func (b *GitHubActionsBuildlet) newInstanceName(hostType string) string {
	b.mu.Lock()
	b.startSeq++
	seq := b.startSeq
	b.mu.Unlock()
	return fmt.Sprintf("buildlet-%s-gha-%d-%s", strings.TrimPrefix(hostType, "host-"), seq, randHex(6))
}
