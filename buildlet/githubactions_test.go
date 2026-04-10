// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildlet

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeGitHubActionsAPI is a test double for the gitHubActionsAPI interface.
type fakeGitHubActionsAPI struct {
	dispatchErr    error
	dispatchCalled bool
	lastInputs     map[string]string
}

func (f *fakeGitHubActionsAPI) DispatchWorkflow(ctx context.Context, owner, repo, workflowFile, gitRef string, inputs map[string]string) error {
	f.dispatchCalled = true
	f.lastInputs = inputs
	return f.dispatchErr
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

	api := &fakeGitHubActionsAPI{}
	c := &GitHubActionsClient{client: api}

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
	if !api.dispatchCalled {
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
	if api.lastInputs["instance_name"] != "inst-1" {
		t.Errorf("dispatch input instance_name = %q, want %q", api.lastInputs["instance_name"], "inst-1")
	}
	if api.lastInputs["host_type"] != "host-test" {
		t.Errorf("dispatch input host_type = %q, want %q", api.lastInputs["host_type"], "host-test")
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
			c := &GitHubActionsClient{client: &fakeGitHubActionsAPI{}}
			_, err := c.StartBuildlet(context.Background(), tc.instName, tc.hostType, tc.opts)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestGitHubActionsDispatchError(t *testing.T) {
	waiter := newFakeBuildletWaiter()
	api := &fakeGitHubActionsAPI{
		dispatchErr: errors.New("API error"),
	}
	c := &GitHubActionsClient{client: api}

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

	api := &fakeGitHubActionsAPI{}
	c := &GitHubActionsClient{client: api}

	opts := &GitHubActionsOpts{
		Repo:         "golang/build@main",
		WorkflowFile: "test.yml",
		Waiter:       waiter,
	}

	_, err := c.StartBuildlet(context.Background(), "inst-1", "host-test", opts)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if api.dispatchCalled != true {
		t.Error("DispatchWorkflow should have been called before the wait error")
	}
}

func TestGitHubActionsDefaultTimeout(t *testing.T) {
	waiter := newFakeBuildletWaiter()
	waiter.waitClient = &FakeClient{}

	api := &fakeGitHubActionsAPI{}
	c := &GitHubActionsClient{client: api}

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

	api := &fakeGitHubActionsAPI{}
	c := &GitHubActionsClient{client: api}

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
