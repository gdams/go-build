// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || darwin

package pool

import (
	"context"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/build/buildenv"
	"golang.org/x/build/buildlet"
	"golang.org/x/build/dashboard"
	"golang.org/x/build/internal/coordinator/pool/queue"
	"golang.org/x/build/internal/rendezvous"
	"golang.org/x/build/internal/secret"
)

var _ Buildlet = (*GHABuildlet)(nil)

// ghaBuildlet is the package level GitHub Actions buildlet pool.
var ghaBuildlet *GHABuildlet

// GHAPool retrieves the package level GHABuildlet pool.
func GHAPool() *GHABuildlet {
	return ghaBuildlet
}

// GHAOpt is optional configuration for the GitHub Actions buildlet pool.
type GHAOpt func(*GHABuildlet)

// GHABuildlet manages a pool of buildlets backed by GitHub Actions runners.
// When a buildlet is requested, it triggers a GitHub Actions workflow_dispatch event
// that starts a GitHub Actions runner. The runner connects to LUCI, then executes
// golangbuild, and finally connects back as a reverse buildlet via the rendezvous system.
type GHABuildlet struct {
	// client handles the GitHub API interaction and buildlet connection.
	client *buildlet.GHAClient
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

// NewGHABuildlet creates a new GitHub Actions buildlet pool.
func NewGHABuildlet(
	buildEnv *buildenv.Environment,
	sc *secret.Client,
	hosts map[string]*dashboard.HostConfig,
	rdv *rendezvous.Rendezvous,
	opts ...GHAOpt,
) (*GHABuildlet, error) {
	b := &GHABuildlet{
		hosts:           hosts,
		rendezvous:      rdv,
		active:          make(map[string]*ghaInstance),
		coordinatorAddr: "farmer.golang.org:443",
	}
	for _, opt := range opts {
		opt(b)
	}

	// In dev mode (no secret client), allow env var overrides
	// with a static GitHub token.
	if sc == nil {
		ghToken := os.Getenv("GHA_GITHUB_TOKEN")
		if v := os.Getenv("GHA_COORDINATOR_ADDR"); v != "" {
			b.coordinatorAddr = v
		}
		b.client = buildlet.NewGHAClient(http.DefaultClient, ghToken)
		ghaBuildlet = b
		return b, nil
	}

	// Production: authenticate as a GitHub App.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	privateKey, err := sc.Retrieve(ctx, secret.NameGHAAppPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("github actions pool: unable to retrieve app private key: %w", err)
	}
	client, err := buildlet.NewGHAClientFromApp(http.DefaultClient, buildEnv.GHAAppClientID, []byte(privateKey))
	if err != nil {
		return nil, fmt.Errorf("github actions pool: %w", err)
	}
	b.client = client

	ghaBuildlet = b
	return b, nil
}

// GetBuildlet triggers a GitHub Actions workflow to provision a Windows 11 ARM
// buildlet. The workflow connects to LUCI, runs golangbuild setup, and then
// connects back as a reverse buildlet through the rendezvous system.
func (b *GHABuildlet) GetBuildlet(ctx context.Context, hostType string, lg Logger, si *queue.SchedItem) (buildlet.Client, error) {
	hconf, ok := b.hosts[hostType]
	if !ok {
		return nil, fmt.Errorf("github actions pool: unknown host type %q", hostType)
	}

	instName := b.newInstanceName(hostType)
	log.Printf("Creating GitHub Actions buildlet %q for %s", instName, hostType)

	// Track the instance.
	b.mu.Lock()
	b.active[instName] = &ghaInstance{
		Name:      instName,
		HostType:  hostType,
		Created:   time.Now(),
		Status:    "dispatching",
		WorkflowS: hconf.GHAWorkflow,
	}
	b.mu.Unlock()

	dispatchSpan := lg.CreateSpan("dispatch_and_wait_github_actions", instName)
	bc, err := b.client.StartBuildlet(ctx, instName, hostType, &buildlet.GHAOpts{
		Repo:            hconf.GHARepo,
		WorkflowFile:    hconf.GHAWorkflow,
		CoordinatorAddr: b.coordinatorAddr,
		Waiter:          b.rendezvous,
		OnWorkflowDispatched: func() {
			b.mu.Lock()
			if inst, ok := b.active[instName]; ok {
				inst.Status = "running"
			}
			b.mu.Unlock()
			log.Printf("GitHub Actions workflow dispatched for %s, waiting for buildlet connection", instName)
		},
	})
	dispatchSpan.Done(err)
	if err != nil {
		b.removeInstance(instName)
		return nil, fmt.Errorf("github actions pool: %s: %w", instName, err)
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

// String gives a report of capacity usage for the GitHub Actions buildlet pool.
func (b *GHABuildlet) String() string {
	b.mu.Lock()
	n := len(b.active)
	b.mu.Unlock()
	return fmt.Sprintf("GitHub Actions pool: %d active instances", n)
}

// WriteHTMLStatus writes the status of the GitHub Actions buildlet pool to an io.Writer.
func (b *GHABuildlet) WriteHTMLStatus(w io.Writer) {
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
func (b *GHABuildlet) buildletDone(instName string) {
	b.removeInstance(instName)
}

// removeInstance removes an instance from the active tracking map.
func (b *GHABuildlet) removeInstance(instName string) {
	b.mu.Lock()
	delete(b.active, instName)
	b.mu.Unlock()
}

// newInstanceName generates a unique instance name for the given host type.
func (b *GHABuildlet) newInstanceName(hostType string) string {
	b.mu.Lock()
	b.startSeq++
	seq := b.startSeq
	b.mu.Unlock()
	return fmt.Sprintf("buildlet-%s-gha-%d-%s", strings.TrimPrefix(hostType, "host-"), seq, randHex(6))
}
