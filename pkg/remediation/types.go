package remediation

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/x7ssss/x7/pkg/triage"
)

// RemediationAction defines an action to fix an operational issue.
type RemediationAction struct {
	ID          string               `json:"id"`
	Subsystem   triage.Subsystem     `json:"subsystem"`
	Target      string               `json:"target"`
	Description string               `json:"description"`
	RemediateFn triage.RemediateFunc `json:"-"`
}

// ConfirmationPrompt handles user confirmation for interactive actions.
type ConfirmationPrompt struct {
	In  io.Reader
	Out io.Writer
}

// Prompt asks the user for confirmation (y/N) on the terminal.
func (p *ConfirmationPrompt) Prompt(message string) (bool, error) {
	fmt.Fprintf(p.Out, "%s [y/N]: ", message)
	reader := bufio.NewReader(p.In)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return false, err
	}
	response := strings.TrimSpace(strings.ToLower(line))
	return response == "y" || response == "yes", nil
}

// GuardRail defines safety validations executed prior to remediation.
type GuardRail interface {
	Name() string
	Validate(ctx context.Context, action RemediationAction) error
}

// DryRunFirstGuardRail verifies that an action succeeds in dry-run mode before actual execution.
type DryRunFirstGuardRail struct{}

func (g *DryRunFirstGuardRail) Name() string {
	return "dry-run-first"
}

func (g *DryRunFirstGuardRail) Validate(ctx context.Context, action RemediationAction) error {
	if action.RemediateFn == nil {
		return fmt.Errorf("remediation function is nil for target: %s", action.Target)
	}
	// Execute dry-run preview first
	if err := action.RemediateFn(ctx, true); err != nil {
		return fmt.Errorf("dry-run validation failed for %s: %w", action.Target, err)
	}
	return nil
}
