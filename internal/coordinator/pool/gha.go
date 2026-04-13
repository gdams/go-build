// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || darwin

package pool

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/build/buildenv"
	"golang.org/x/build/buildlet"
	"golang.org/x/build/dashboard"
	"golang.org/x/build/internal/secret"
)

var _ ReverseProvisioner = (*GHAProvisioner)(nil)

// GHAOpt is optional configuration for the GitHub Actions provisioner.
type GHAOpt func(*GHAProvisioner)

// GHAProvisioner provisions reverse buildlets via GitHub Actions workflows.
// When a buildlet is requested, it triggers a GitHub Actions workflow_dispatch
// event that starts a runner which connects back as a reverse buildlet.
// It implements ReverseProvisioner and is registered with the reverse pool.
type GHAProvisioner struct {
	// client handles the GitHub API interaction and buildlet connection.
	client *buildlet.GHAClient
	// coordinatorAddr is the address the workflow runner should connect back to.
	coordinatorAddr string
	// hosts provides the host configuration for all hosts.
	hosts map[string]*dashboard.HostConfig
}

// NewGHAProvisioner creates a new GitHub Actions provisioner and registers
// it with the reverse pool for all GHA-backed host types.
func NewGHAProvisioner(
	buildEnv *buildenv.Environment,
	sc *secret.Client,
	hosts map[string]*dashboard.HostConfig,
	opts ...GHAOpt,
) error {
	b := &GHAProvisioner{
		hosts:           hosts,
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
		b.registerWithReversePool()
		return nil
	}

	// Production: authenticate as a GitHub App.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	privateKey, err := sc.Retrieve(ctx, secret.NameGHAAppPrivateKey)
	if err != nil {
		return fmt.Errorf("github actions provisioner: unable to retrieve app private key: %w", err)
	}
	client, err := buildlet.NewGHAClientFromApp(http.DefaultClient, buildEnv.GHAAppClientID, []byte(privateKey))
	if err != nil {
		return fmt.Errorf("github actions provisioner: %w", err)
	}
	b.client = client

	b.registerWithReversePool()
	return nil
}

// registerWithReversePool registers this provisioner with the reverse pool
// for all host types that have GHA configuration.
func (b *GHAProvisioner) registerWithReversePool() {
	for hostType, hconf := range b.hosts {
		if hconf.IsGHA {
			reversePool.RegisterProvisioner(hostType, b)
		}
	}
}

// ProvisionBuildlet triggers a GitHub Actions workflow to provision a buildlet.
// The workflow connects back as a reverse buildlet through the standard
// /reverse endpoint.
func (b *GHAProvisioner) ProvisionBuildlet(ctx context.Context, instName, hostType string, waiter buildlet.BuildletWaiter, lg Logger) (buildlet.Client, error) {
	hconf, ok := b.hosts[hostType]
	if !ok {
		return nil, fmt.Errorf("github actions provisioner: unknown host type %q", hostType)
	}

	log.Printf("Creating GitHub Actions buildlet %q for %s", instName, hostType)

	dispatchSpan := lg.CreateSpan("dispatch_and_wait_github_actions", instName)
	bc, err := b.client.StartBuildlet(ctx, instName, hostType, &buildlet.GHAOpts{
		Repo:            hconf.GHARepo,
		WorkflowFile:    hconf.GHAWorkflow,
		CoordinatorAddr: b.coordinatorAddr,
		Waiter:          waiter,
		OnWorkflowDispatched: func() {
			log.Printf("GitHub Actions workflow dispatched for %s, waiting for buildlet connection", instName)
		},
	})
	dispatchSpan.Done(err)
	if err != nil {
		return nil, fmt.Errorf("github actions provisioner: %s: %w", instName, err)
	}

	return bc, nil
}
