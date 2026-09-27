package remediation

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/x7ssss/x7/pkg/triage"
)

// ExecutorConfig configures remediation execution.
type ExecutorConfig struct {
	DryRun      bool
	Interactive bool
	Force       bool
	In          io.Reader
	Out         io.Writer
}

// RemediationResult records the execution outcome of an action.
type RemediationResult struct {
	Action RemediationAction
	Status string // DRY-RUN, APPLIED, SKIPPED, FAILED
	Error  error
}

// Executor coordinates safe two-phase dry-run-first remediation.
type Executor struct {
	config     ExecutorConfig
	guardRails []GuardRail
	prompter   *ConfirmationPrompt
}

// NewExecutor creates a new Executor instance with standard guardrails.
func NewExecutor(cfg ExecutorConfig) *Executor {
	return &Executor{
		config: cfg,
		guardRails: []GuardRail{
			&DryRunFirstGuardRail{},
		},
		prompter: &ConfirmationPrompt{
			In:  cfg.In,
			Out: cfg.Out,
		},
	}
}

// FilterRemediable extracts remediable actions from triage diagnostic results.
func FilterRemediable(results []triage.DiagnosticResult) []RemediationAction {
	actions := make([]RemediationAction, 0)
	for _, r := range results {
		if r.Remediable && r.RemediateFn != nil {
			actions = append(actions, RemediationAction{
				ID:          r.ID,
				Subsystem:   r.Subsystem,
				Target:      r.Target,
				Description: r.Summary,
				RemediateFn: r.RemediateFn,
			})
		}
	}
	return actions
}

// Execute executes remediation across the provided actions with two-phase safety.
func (e *Executor) Execute(ctx context.Context, actions []RemediationAction) ([]RemediationResult, error) {
	if len(actions) == 0 {
		fmt.Fprintln(e.config.Out, "No remediable issues identified.")
		return nil, nil
	}

	fmt.Fprintln(e.config.Out, "========================================================================================")
	fmt.Fprintf(e.config.Out, "REMEDIATION PLAN: %d actionable items queued\n", len(actions))
	fmt.Fprintln(e.config.Out, "========================================================================================")
	for i, act := range actions {
		fmt.Fprintf(e.config.Out, "  [%d] [%s] %s : %s\n", i+1, strings.ToUpper(string(act.Subsystem)), act.Target, act.Description)
	}
	fmt.Fprintln(e.config.Out, "----------------------------------------------------------------------------------------")

	results := make([]RemediationResult, 0, len(actions))

	if e.config.DryRun {
		fmt.Fprintln(e.config.Out, "[MODE: DRY-RUN PREVIEW] No live changes will be committed.")
		fmt.Fprintln(e.config.Out)

		for _, act := range actions {
			err := act.RemediateFn(ctx, true)
			if err != nil {
				fmt.Fprintf(e.config.Out, "  [-] %s : FAILED (dry-run preview error: %v)\n", act.Target, err)
				results = append(results, RemediationResult{
					Action: act,
					Status: "FAILED",
					Error:  err,
				})
			} else {
				fmt.Fprintf(e.config.Out, "  [-] %s : DRY-RUN (safe to apply)\n", act.Target)
				results = append(results, RemediationResult{
					Action: act,
					Status: "DRY-RUN",
				})
			}
		}
		return results, nil
	}

	// Live mode with safe two-phase dry-run validation
	fmt.Fprintln(e.config.Out, "[MODE: LIVE REMEDIATION] Executing two-phase safe application...")
	fmt.Fprintln(e.config.Out)

	for _, act := range actions {
		// Phase 1: GuardRail dry-run validation
		var guardErr error
		for _, g := range e.guardRails {
			if err := g.Validate(ctx, act); err != nil {
				guardErr = err
				break
			}
		}
		if guardErr != nil {
			fmt.Fprintf(e.config.Out, "  [-] %s : GUARD-RAIL REJECTED (%v)\n", act.Target, guardErr)
			results = append(results, RemediationResult{
				Action: act,
				Status: "FAILED",
				Error:  guardErr,
			})
			continue
		}

		// Interactive confirmation check
		if e.config.Interactive && !e.config.Force {
			confirmMsg := fmt.Sprintf("Apply remediation for %s (%s)?", act.Target, act.Description)
			confirmed, promptErr := e.prompter.Prompt(confirmMsg)
			if promptErr != nil || !confirmed {
				fmt.Fprintf(e.config.Out, "  [-] %s : SKIPPED (user cancelled)\n", act.Target)
				results = append(results, RemediationResult{
					Action: act,
					Status: "SKIPPED",
				})
				continue
			}
		}

		// Phase 2: Live execution
		applyErr := act.RemediateFn(ctx, false)
		if applyErr != nil {
			fmt.Fprintf(e.config.Out, "  [-] %s : FAILED (%v)\n", act.Target, applyErr)
			results = append(results, RemediationResult{
				Action: act,
				Status: "FAILED",
				Error:  applyErr,
			})
		} else {
			fmt.Fprintf(e.config.Out, "  [-] %s : APPLIED (remediation successful)\n", act.Target)
			results = append(results, RemediationResult{
				Action: act,
				Status: "APPLIED",
			})
		}
	}

	return results, nil
}
