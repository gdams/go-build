// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildlet

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v74/github"
	"golang.org/x/oauth2"
)

// BuildletWaiter provides a mechanism to wait for a reverse buildlet connection.
// The rendezvous.Rendezvous type satisfies this interface.
type BuildletWaiter interface {
	RegisterInstance(ctx context.Context, id string, wait time.Duration)
	WaitForInstance(ctx context.Context, id string) (Client, error)
	DeregisterInstance(ctx context.Context, id string)
}

// GHAClient is the client used to create buildlets via GitHub Actions
// workflow_dispatch events. It mirrors the pattern of EC2Client: a thin wrapper
// around a cloud API that dispatches work and returns a connected Client.
type GHAClient struct {
	client *ghAPIClient
}

// NewGHAClient creates a new GHAClient that authenticates
// using a static token. This is intended for development and testing.
func NewGHAClient(httpClient *http.Client, token string) *GHAClient {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return &GHAClient{
		client: &ghAPIClient{
			httpClient: &http.Client{
				Transport: &oauth2.Transport{
					Source: ts,
					Base:   httpClient.Transport,
				},
			},
			clients: make(map[int64]*github.Client),
		},
	}
}

// NewGHAClientFromApp creates a new GHAClient that
// authenticates as a GitHub App. It generates short-lived installation
// tokens on demand using the app's private key. The installation ID
// for each target repository is resolved dynamically.
func NewGHAClientFromApp(httpClient *http.Client, clientID int64, privateKeyPEM []byte) (*GHAClient, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return &GHAClient{
		client: &ghAPIClient{
			httpClient: httpClient,
			clientID:   clientID,
			privateKey: key,
			instIDs:    make(map[string]int64),
			clients:    make(map[int64]*github.Client),
		},
	}, nil
}

// GHAOpts contains options for dispatching a GitHub Actions buildlet.
type GHAOpts struct {
	// Repo is the GitHub repository in "owner/repo@ref" format
	// (e.g. "golang/build@main").
	Repo string
	// WorkflowFile is the workflow filename to dispatch (e.g. "win11-arm-buildlet.yml").
	WorkflowFile string
	// CoordinatorAddr is the address the workflow runner should connect back to.
	CoordinatorAddr string
	// Waiter provides the mechanism for waiting for the reverse buildlet connection.
	Waiter BuildletWaiter
	// RegistrationTimeout is how long to wait for the runner to connect back.
	// Defaults to 30 minutes if zero.
	RegistrationTimeout time.Duration

	// OnWorkflowDispatched optionally specifies a hook to run synchronously
	// after the workflow dispatch call succeeds.
	OnWorkflowDispatched func()
}

// StartBuildlet dispatches a GitHub Actions workflow to provision a buildlet
// and waits for the runner to connect back as a reverse buildlet via the waiter.
func (c *GHAClient) StartBuildlet(ctx context.Context, instName, hostType string, opts *GHAOpts) (Client, error) {
	if opts == nil {
		return nil, fmt.Errorf("options must be set")
	}
	if opts.Waiter == nil {
		return nil, fmt.Errorf("waiter must be set")
	}
	if instName == "" || hostType == "" {
		return nil, fmt.Errorf("invalid instName: %q and hostType: %q", instName, hostType)
	}

	owner, repo, gitRef, err := parseRepo(opts.Repo)
	if err != nil {
		return nil, err
	}

	timeout := opts.RegistrationTimeout
	if timeout == 0 {
		timeout = 30 * time.Minute
	}

	// Register with the waiter before dispatching so the runner can connect back.
	opts.Waiter.RegisterInstance(ctx, instName, timeout)

	inputs := map[string]any{
		"instance_name": instName,
		"host_type":     hostType,
		"coordinator":   opts.CoordinatorAddr,
	}
	if err := c.client.DispatchWorkflow(ctx, owner, repo, opts.WorkflowFile, gitRef, inputs); err != nil {
		opts.Waiter.DeregisterInstance(ctx, instName)
		return nil, fmt.Errorf("dispatch workflow: %w", err)
	}
	condRun(opts.OnWorkflowDispatched)

	// Wait for the runner to connect back via the reverse buildlet mechanism.
	bc, err := opts.Waiter.WaitForInstance(ctx, instName)
	if err != nil {
		return nil, fmt.Errorf("wait for buildlet: %w", err)
	}
	return bc, nil
}

// parseRepo parses a repo string in "owner/repo@ref" format.
func parseRepo(s string) (owner, repo, ref string, err error) {
	parts := strings.SplitN(s, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", "", fmt.Errorf("invalid repo %q: expected owner/repo@ref", s)
	}
	ref = parts[1]
	ownerRepo := strings.SplitN(parts[0], "/", 2)
	if len(ownerRepo) != 2 || ownerRepo[0] == "" || ownerRepo[1] == "" {
		return "", "", "", fmt.Errorf("invalid repo %q: expected owner/repo@ref", s)
	}
	return ownerRepo[0], ownerRepo[1], ref, nil
}

// ghAPIClient implements ghaAPI using the go-github library.
// In static token mode (privateKey is nil), httpClient already carries
// the oauth2 transport and a single github.Client is cached.
// In GitHub App mode (privateKey is set), it dynamically resolves
// installation IDs per-repository and caches a github.Client per
// installation ID, each using an installTokenTransport that
// automatically refreshes the installation token when it expires.
type ghAPIClient struct {
	httpClient *http.Client
	clientID   int64
	privateKey *rsa.PrivateKey
	apiBaseURL string // for testing; if empty, uses GitHub's default API URL

	mu      sync.Mutex
	instIDs map[string]int64         // "owner/repo" -> installation ID
	clients map[int64]*github.Client // installation ID -> cached client
}

func (c *ghAPIClient) DispatchWorkflow(ctx context.Context, owner, repo, workflowFile, gitRef string, inputs map[string]any) error {
	ghClient, err := c.clientForRepo(ctx, owner, repo)
	if err != nil {
		return err
	}
	_, err = ghClient.Actions.CreateWorkflowDispatchEventByFileName(ctx, owner, repo, workflowFile, github.CreateWorkflowDispatchEventRequest{
		Ref:    gitRef,
		Inputs: inputs,
	})
	return err
}

// clientForRepo returns a github.Client for the given repository.
// In static token mode it returns a single cached client.
// In App mode, clients are cached per installation ID and their
// transport refreshes the token automatically when it expires.
func (c *ghAPIClient) clientForRepo(ctx context.Context, owner, repo string) (*github.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.privateKey == nil {
		if gh, ok := c.clients[0]; ok {
			return gh, nil
		}
		gh := github.NewClient(c.httpClient)
		if c.apiBaseURL != "" {
			gh, _ = gh.WithEnterpriseURLs(c.apiBaseURL, c.apiBaseURL)
		}
		c.clients[0] = gh
		return gh, nil
	}

	key := owner + "/" + repo
	instID, ok := c.instIDs[key]
	if !ok {
		// Look up the installation ID for this repo.
		jwtClient, err := c.jwtClient()
		if err != nil {
			return nil, err
		}
		install, _, err := jwtClient.Apps.FindRepositoryInstallation(ctx, owner, repo)
		if err != nil {
			return nil, fmt.Errorf("find repository installation for %s: %w", key, err)
		}
		instID = install.GetID()
		c.instIDs[key] = instID
	}

	if gh, ok := c.clients[instID]; ok {
		return gh, nil
	}

	// Create a new client with a self-refreshing transport.
	t := &installTokenTransport{
		app:    c,
		instID: instID,
		base:   c.httpClient.Transport,
	}
	ghClient := github.NewClient(&http.Client{Transport: t})
	if c.apiBaseURL != "" {
		ghClient, _ = ghClient.WithEnterpriseURLs(c.apiBaseURL, c.apiBaseURL)
	}
	c.clients[instID] = ghClient
	return ghClient, nil
}

// jwtClient returns a github.Client authenticated with a short-lived App JWT.
func (c *ghAPIClient) jwtClient() (*github.Client, error) {
	jwt, err := c.signJWT()
	if err != nil {
		return nil, fmt.Errorf("sign app JWT: %w", err)
	}
	httpClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: jwt}),
			Base:   c.httpClient.Transport,
		},
	}
	ghClient := github.NewClient(httpClient)
	if c.apiBaseURL != "" {
		ghClient, _ = ghClient.WithEnterpriseURLs(c.apiBaseURL, c.apiBaseURL)
	}
	return ghClient, nil
}

// installTokenTransport is an http.RoundTripper that authenticates requests
// using a GitHub App installation token, refreshing it when it expires.
type installTokenTransport struct {
	app    *ghAPIClient
	instID int64
	base   http.RoundTripper

	mu  sync.Mutex
	tok *oauth2.Token
}

func (t *installTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.token(req.Context())
	if err != nil {
		return nil, err
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

func (t *installTokenTransport) token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tok != nil && t.tok.Valid() {
		return t.tok.AccessToken, nil
	}

	jwtClient, err := t.app.jwtClient()
	if err != nil {
		return "", err
	}
	instToken, _, err := jwtClient.Apps.CreateInstallationToken(ctx, t.instID, nil)
	if err != nil {
		return "", fmt.Errorf("create installation token: %w", err)
	}
	t.tok = &oauth2.Token{
		AccessToken: instToken.GetToken(),
		Expiry:      instToken.GetExpiresAt().Time.Add(-time.Minute),
	}
	return t.tok.AccessToken, nil
}

// signJWT creates a short-lived JWT for authenticating as the GitHub App.
func (c *ghAPIClient) signJWT() (string, error) {
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iss": c.clientID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(claims)
	signingInput := header + "." + payload
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
