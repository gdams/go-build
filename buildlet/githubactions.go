// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildlet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// gitHubActionsAPI represents the GitHub API calls needed for dispatching workflows.
// This interface exists for testability, allowing tests to inject a fake implementation.
type gitHubActionsAPI interface {
	DispatchWorkflow(ctx context.Context, owner, repo, workflowFile, gitRef string, inputs map[string]string) error
}

// BuildletWaiter provides a mechanism to wait for a reverse buildlet connection.
// The rendezvous.Rendezvous type satisfies this interface.
type BuildletWaiter interface {
	RegisterInstance(ctx context.Context, id string, wait time.Duration)
	WaitForInstance(ctx context.Context, id string) (Client, error)
	DeregisterInstance(ctx context.Context, id string)
}

// GitHubActionsClient is the client used to create buildlets via GitHub Actions
// workflow_dispatch events. It mirrors the pattern of EC2Client: a thin wrapper
// around a cloud API that dispatches work and returns a connected Client.
type GitHubActionsClient struct {
	client gitHubActionsAPI
}

// NewGitHubActionsClient creates a new GitHubActionsClient.
func NewGitHubActionsClient(httpClient *http.Client, token string) *GitHubActionsClient {
	return &GitHubActionsClient{
		client: &ghAPIClient{httpClient: httpClient, token: token},
	}
}

// GitHubActionsOpts contains options for dispatching a GitHub Actions buildlet.
type GitHubActionsOpts struct {
	// Owner is the GitHub repository owner (e.g. "golang").
	Owner string
	// Repo is the GitHub repository name (e.g. "build").
	Repo string
	// WorkflowFile is the workflow filename to dispatch (e.g. "win11-arm-buildlet.yml").
	WorkflowFile string
	// GitRef is the git ref (branch) to dispatch the workflow on.
	GitRef string
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
func (c *GitHubActionsClient) StartBuildlet(ctx context.Context, instName, hostType string, opts *GitHubActionsOpts) (Client, error) {
	if opts == nil {
		return nil, fmt.Errorf("options must be set")
	}
	if opts.Waiter == nil {
		return nil, fmt.Errorf("waiter must be set")
	}
	if instName == "" || hostType == "" {
		return nil, fmt.Errorf("invalid instName: %q and hostType: %q", instName, hostType)
	}

	timeout := opts.RegistrationTimeout
	if timeout == 0 {
		timeout = 30 * time.Minute
	}

	// Register with the waiter before dispatching so the runner can connect back.
	opts.Waiter.RegisterInstance(ctx, instName, timeout)

	inputs := map[string]string{
		"instance_name": instName,
		"host_type":     hostType,
		"coordinator":   opts.CoordinatorAddr,
	}
	if err := c.client.DispatchWorkflow(ctx, opts.Owner, opts.Repo, opts.WorkflowFile, opts.GitRef, inputs); err != nil {
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

// ghAPIClient is the real GitHub API client implementation.
type ghAPIClient struct {
	httpClient *http.Client
	token      string
}

func (c *ghAPIClient) DispatchWorkflow(ctx context.Context, owner, repo, workflowFile, gitRef string, inputs map[string]string) error {
	payload := map[string]interface{}{
		"ref":    gitRef,
		"inputs": inputs,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal dispatch payload: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/workflows/%s/dispatches",
		owner, repo, workflowFile)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create dispatch request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("dispatch returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
