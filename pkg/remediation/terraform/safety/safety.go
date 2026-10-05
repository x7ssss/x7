package safety

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/x7ssss/x7/pkg/remediation/terraform/backend"
	"github.com/x7ssss/x7/pkg/remediation/terraform/ghrun"
)

// DefaultStaleThreshold is the default staleness threshold for state locks.
const DefaultStaleThreshold = 30 * time.Minute

// VerifyStaleness verifies whether a lock is old enough to be broken safely.
// If the lock is younger than staleAfter and force is false, an error is returned.
func VerifyStaleness(lock *backend.LockInfo, staleAfter time.Duration, force bool) error {
	if force || lock == nil {
		return nil
	}

	if lock.Created.IsZero() {
		// When creation timestamp is absent, allow proceed unless forced otherwise
		return nil
	}

	age := lock.Age()
	if age < staleAfter {
		return fmt.Errorf("refusing to break active lock %q: lock age %s is less than staleness threshold %s (created %s); use --force to override",
			lock.ID, FormatDuration(age), FormatDuration(staleAfter), lock.Created.Format(time.RFC3339))
	}

	return nil
}

// VerifyLockID ensures that the active lock matches the user-specified lock ID.
func VerifyLockID(lock *backend.LockInfo, requestedID string) error {
	if requestedID == "" || lock == nil {
		return nil
	}

	requested := strings.TrimSpace(requestedID)
	active := strings.TrimSpace(lock.ID)

	if requested != active {
		return fmt.Errorf("lock ID mismatch: active lock is %q, but requested ID is %q", active, requested)
	}

	return nil
}

// IsTerminal checks if the given file handle is an interactive terminal.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ConfirmBreak prompts the user for interactive confirmation to release a lock.
func ConfirmBreak(in io.Reader, out io.Writer, lockID string, force bool, nonInteractive bool) (bool, error) {
	if force || nonInteractive {
		return true, nil
	}

	fmt.Fprintf(out, "Are you sure you want to break lock %s? (yes/no): ", lockID)

	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, fmt.Errorf("failed to read user confirmation: %w", err)
		}
		return false, errors.New("aborted: end of input received")
	}

	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer == "yes" || answer == "y" {
		return true, nil
	}

	return false, nil
}

// FormatDuration formats a time.Duration into a clean, human-readable string.
func FormatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

// RunLookup resolves a workflow run's state.
type RunLookup interface {
	GetRun(ctx context.Context, repo, runID string) (*ghrun.Run, error)
}

// VerifyRunnerTerminated refuses to proceed while the lock holder's workflow run
// is still active. Lookup failures are fatal unless force is set (fail closed).
func VerifyRunnerTerminated(ctx context.Context, lookup RunLookup, repo, runID string, force bool) error {
	if force || runID == "" {
		return nil
	}
	run, err := lookup.GetRun(ctx, repo, runID)
	if err != nil {
		return fmt.Errorf("could not verify runner termination for run %s: %w", runID, err)
	}
	if run.Classify() != ghrun.Terminal {
		return fmt.Errorf("refusing to break lock: run %s is still active (status=%s); wait for it to finish or use --force", runID, run.Status)
	}
	return nil
}
