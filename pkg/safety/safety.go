package safety

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// DefaultStaleThreshold is the default staleness threshold for infrastructure locks.
const DefaultStaleThreshold = 30 * time.Minute

// ProtectedNamespaces lists critical cluster namespaces that cannot be mutated or purged without explicit overrides.
var ProtectedNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"default",
}

// VerifyStaleness verifies whether a timestamped object is old enough to be safely remediated.
// If the object age is less than staleAfter and force is false, an error is returned.
func VerifyStaleness(created time.Time, staleAfter time.Duration, force bool) error {
	if force || created.IsZero() {
		return nil
	}

	age := time.Since(created)
	if age < staleAfter {
		return fmt.Errorf("refusing remediation: age %s is less than staleness threshold %s (created %s); use --force to override",
			FormatDuration(age), FormatDuration(staleAfter), created.Format(time.RFC3339))
	}

	return nil
}

// VerifyLockID ensures that the active lock identifier matches the requested ID.
func VerifyLockID(activeID, expectedID string) error {
	if expectedID == "" {
		return nil
	}

	active := strings.TrimSpace(activeID)
	expected := strings.TrimSpace(expectedID)

	if active != expected {
		return fmt.Errorf("lock ID mismatch: active lock is %q, but requested ID is %q", active, expected)
	}

	return nil
}

// IsTerminal checks if the given file handle is an interactive terminal character device.
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

// ConfirmPrompt prompts the user for interactive confirmation on a terminal.
func ConfirmPrompt(in io.Reader, out io.Writer, message string, force bool, nonInteractive bool) (bool, error) {
	if force || nonInteractive {
		return true, nil
	}

	if in == nil {
		return false, errors.New("cannot prompt for confirmation: stdin reader is nil")
	}

	if out == nil {
		out = os.Stdout
	}

	fmt.Fprintf(out, "%s (yes/no): ", message)

	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, fmt.Errorf("failed to read user confirmation: %w", err)
		}
		return false, errors.New("aborted: end of input received")
	}

	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "yes" || answer == "y", nil
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

// VerifyBlastRadiusLimit enforces that the number of affected resources does not exceed a tolerance limit.
func VerifyBlastRadiusLimit(affectedCount, maxAllowed int, force bool) error {
	if force {
		return nil
	}
	if maxAllowed > 0 && affectedCount > maxAllowed {
		return fmt.Errorf("blast radius exceeded: remediation affects %d resources, which exceeds the limit of %d; use --force to override",
			affectedCount, maxAllowed)
	}
	return nil
}

// VerifyNamespaceSafety ensures high-risk system namespaces are protected against accidental remediation/purge.
func VerifyNamespaceSafety(namespace string, force bool) error {
	if force {
		return nil
	}
	for _, protected := range ProtectedNamespaces {
		if strings.EqualFold(strings.TrimSpace(namespace), protected) {
			return fmt.Errorf("protected namespace violation: refusing destructive operation on %q without --force", namespace)
		}
	}
	return nil
}
