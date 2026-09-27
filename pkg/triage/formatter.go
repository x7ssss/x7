package triage

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Formatter formats diagnostic results into terminal or structured outputs.
type Formatter struct{}

// NewFormatter creates a new Formatter.
func NewFormatter() *Formatter {
	return &Formatter{}
}

// FormatText formats diagnostic results into brutalist monospace terminal output.
func (f *Formatter) FormatText(w io.Writer, results []DiagnosticResult) {
	k8sResults := make([]DiagnosticResult, 0)
	dbResults := make([]DiagnosticResult, 0)
	infraResults := make([]DiagnosticResult, 0)

	deadlockCount := 0

	for _, r := range results {
		if r.Severity == SeverityDeadlock || r.Severity == SeverityCritical {
			deadlockCount++
		}
		switch r.Subsystem {
		case SubsystemK8s:
			k8sResults = append(k8sResults, r)
		case SubsystemDB:
			dbResults = append(dbResults, r)
		case SubsystemInfra:
			infraResults = append(infraResults, r)
		default:
			infraResults = append(infraResults, r)
		}
	}

	fmt.Fprintln(w, "[KUBERNETES]")
	if len(k8sResults) == 0 {
		fmt.Fprintln(w, "  [-] No issues detected")
	} else {
		for _, r := range k8sResults {
			fmt.Fprintf(w, "  [-] %s : %s (%s)\n", r.Target, r.Severity, r.Summary)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[STORAGE & DATABASES]")
	if len(dbResults) == 0 {
		fmt.Fprintln(w, "  [-] No issues detected")
	} else {
		for _, r := range dbResults {
			fmt.Fprintf(w, "  [-] %s : %s (%s)\n", r.Target, r.Severity, r.Summary)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "[INFRASTRUCTURE & STATE]")
	if len(infraResults) == 0 {
		fmt.Fprintln(w, "  [-] No issues detected")
	} else {
		for _, r := range infraResults {
			fmt.Fprintf(w, "  [-] %s : %s (%s)\n", r.Target, r.Severity, r.Summary)
		}
	}
	fmt.Fprintln(w)

	divider := strings.Repeat("=", 88)
	fmt.Fprintln(w, divider)
	if deadlockCount > 0 {
		fmt.Fprintf(w, "VERDICT: %d actionable production deadlocks detected.\n", deadlockCount)
		fmt.Fprintln(w, "Run 'x7 heal --interactive' or target specific subsystems (e.g. 'x7 heal k8s').")
	} else {
		fmt.Fprintln(w, "VERDICT: 0 actionable production deadlocks detected.")
	}
}

// FormatJSON formats diagnostic results as indented JSON.
func (f *Formatter) FormatJSON(w io.Writer, results []DiagnosticResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
