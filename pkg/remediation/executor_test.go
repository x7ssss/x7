package remediation

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/x7ssss/x7/pkg/triage"
)

func TestExecutor_DryRun(t *testing.T) {
	dryRunCalled := false
	liveCalled := false

	actions := []RemediationAction{
		{
			ID:          "act-1",
			Subsystem:   triage.SubsystemK8s,
			Target:      "Helm Release 'vault'",
			Description: "Reset pending release",
			RemediateFn: func(ctx context.Context, dryRun bool) error {
				if dryRun {
					dryRunCalled = true
					return nil
				}
				liveCalled = true
				return nil
			},
		},
	}

	var out bytes.Buffer
	cfg := ExecutorConfig{
		DryRun: true,
		Out:    &out,
	}

	executor := NewExecutor(cfg)
	results, err := executor.Execute(context.Background(), actions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !dryRunCalled {
		t.Errorf("expected dry-run preview to be called")
	}
	if liveCalled {
		t.Errorf("live remediation should not be called in dry-run mode")
	}
	if len(results) != 1 || results[0].Status != "DRY-RUN" {
		t.Errorf("expected 1 DRY-RUN result, got %+v", results)
	}
}

func TestExecutor_LiveApplication(t *testing.T) {
	dryRunCount := 0
	liveCount := 0

	actions := []RemediationAction{
		{
			ID:          "act-live",
			Subsystem:   triage.SubsystemInfra,
			Target:      "Terraform Lock 'stale-lock'",
			Description: "Remove stale lock",
			RemediateFn: func(ctx context.Context, dryRun bool) error {
				if dryRun {
					dryRunCount++
					return nil
				}
				liveCount++
				return nil
			},
		},
	}

	var out bytes.Buffer
	cfg := ExecutorConfig{
		DryRun: false,
		Force:  true,
		Out:    &out,
	}

	executor := NewExecutor(cfg)
	results, err := executor.Execute(context.Background(), actions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Two-phase execution: phase 1 dry-run guardrail + phase 2 live
	if dryRunCount != 1 {
		t.Errorf("expected guardrail dry-run to execute once, got %d", dryRunCount)
	}
	if liveCount != 1 {
		t.Errorf("expected live execution once, got %d", liveCount)
	}
	if len(results) != 1 || results[0].Status != "APPLIED" {
		t.Errorf("expected APPLIED result, got %+v", results)
	}
}

func TestExecutor_GuardRailRejection(t *testing.T) {
	actions := []RemediationAction{
		{
			ID:          "act-failing-dryrun",
			Subsystem:   triage.SubsystemK8s,
			Target:      "Namespace 'stuck'",
			Description: "Remove finalizers",
			RemediateFn: func(ctx context.Context, dryRun bool) error {
				if dryRun {
					return errors.New("dry-run simulation failed: resource not found")
				}
				return nil
			},
		},
	}

	var out bytes.Buffer
	cfg := ExecutorConfig{
		DryRun: false,
		Force:  true,
		Out:    &out,
	}

	executor := NewExecutor(cfg)
	results, err := executor.Execute(context.Background(), actions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 || results[0].Status != "FAILED" {
		t.Errorf("expected FAILED status due to guardrail rejection, got %+v", results)
	}
}

func TestExecutor_InteractivePrompt(t *testing.T) {
	applied := false
	actions := []RemediationAction{
		{
			ID:          "act-prompt",
			Subsystem:   triage.SubsystemDB,
			Target:      "Postgres Database 'analytics'",
			Description: "Vacuum freeze",
			RemediateFn: func(ctx context.Context, dryRun bool) error {
				if !dryRun {
					applied = true
				}
				return nil
			},
		},
	}

	// User responds 'y'
	var in bytes.Buffer
	in.WriteString("y\n")
	var out bytes.Buffer

	cfg := ExecutorConfig{
		DryRun:      false,
		Interactive: true,
		Force:       false,
		In:          &in,
		Out:         &out,
	}

	executor := NewExecutor(cfg)
	results, err := executor.Execute(context.Background(), actions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !applied {
		t.Errorf("expected remediation to be applied after 'y' confirmation")
	}
	if len(results) != 1 || results[0].Status != "APPLIED" {
		t.Errorf("expected APPLIED result, got %+v", results)
	}

	// User responds 'n'
	applied = false
	in.Reset()
	in.WriteString("n\n")
	out.Reset()

	results, err = executor.Execute(context.Background(), actions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if applied {
		t.Errorf("remediation should NOT be applied after 'n' rejection")
	}
	if len(results) != 1 || results[0].Status != "SKIPPED" {
		t.Errorf("expected SKIPPED result, got %+v", results)
	}
}

func TestFilterRemediable(t *testing.T) {
	results := []triage.DiagnosticResult{
		{
			ID:         "r1",
			Remediable: true,
			RemediateFn: func(ctx context.Context, dryRun bool) error {
				return nil
			},
		},
		{
			ID:          "r2",
			Remediable:  false,
			RemediateFn: nil,
		},
	}

	actions := FilterRemediable(results)
	if len(actions) != 1 || actions[0].ID != "r1" {
		t.Errorf("expected only remediable actions with non-nil RemediateFn, got %+v", actions)
	}
}

// Unused dummy import helper
var _ = strings.ToUpper
