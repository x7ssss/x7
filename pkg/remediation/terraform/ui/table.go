package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/x7ssss/x7/pkg/remediation/terraform/backend"
	"github.com/x7ssss/x7/pkg/remediation/terraform/safety"
)

// ANSI color escapes
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return safety.IsTerminal(os.Stdout)
}

func colorize(code, text string) string {
	if !useColor() {
		return text
	}
	return code + text + colorReset
}

// RenderLockInfo renders detailed brutalist table for an active lock.
func RenderLockInfo(w io.Writer, lock *backend.LockInfo, staleThreshold time.Duration) {
	width := 80
	border := "+" + strings.Repeat("-", width-2) + "+"

	var statusBadge string
	var stalenessDetail string
	age := lock.Age()

	if lock.IsStale(staleThreshold) {
		statusBadge = colorize(colorYellow+colorBold, "[LOCKED - STALE]")
		stalenessDetail = fmt.Sprintf("STALE (age %s exceeds %s threshold)",
			safety.FormatDuration(age), safety.FormatDuration(staleThreshold))
	} else {
		statusBadge = colorize(colorRed+colorBold, "[LOCKED - ACTIVE]")
		stalenessDetail = fmt.Sprintf("ACTIVE (age %s is under %s threshold)",
			safety.FormatDuration(age), safety.FormatDuration(staleThreshold))
	}

	createdStr := "Unknown"
	if !lock.Created.IsZero() {
		createdStr = fmt.Sprintf("%s (%s ago)", lock.Created.Format(time.RFC3339), safety.FormatDuration(age))
	}

	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "|  %s\n", colorize(colorBold, "TF-UNLOCK :: REMOTE STATE LOCK INSPECTOR"))
	fmt.Fprintln(w, border)
	printRow(w, "STATUS", statusBadge, width)
	printRow(w, "LOCK ID", lock.ID, width)
	printRow(w, "BACKEND", lock.BackendType, width)
	printRow(w, "TARGET", lock.Target, width)
	if lock.Operation != "" {
		printRow(w, "OPERATION", lock.Operation, width)
	}
	if lock.Who != "" {
		printRow(w, "WHO", lock.Who, width)
	}
	if lock.Version != "" {
		printRow(w, "VERSION", lock.Version, width)
	}
	printRow(w, "CREATED", createdStr, width)
	printRow(w, "STALENESS", stalenessDetail, width)
	if lock.Path != "" {
		printRow(w, "PATH", lock.Path, width)
	}
	if lock.Info != "" {
		printRow(w, "INFO", lock.Info, width)
	}
	if lock.ETag != "" {
		printRow(w, "ETAG", lock.ETag, width)
	}
	fmt.Fprintln(w, border)
}

// RenderClean renders brutalist status box when no lock is found.
func RenderClean(w io.Writer, backendType, target string) {
	width := 80
	border := "+" + strings.Repeat("-", width-2) + "+"

	statusBadge := colorize(colorGreen+colorBold, "[UNLOCKED - CLEAN]")

	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "|  %s\n", colorize(colorBold, "TF-UNLOCK :: REMOTE STATE LOCK INSPECTOR"))
	fmt.Fprintln(w, border)
	printRow(w, "STATUS", statusBadge, width)
	printRow(w, "BACKEND", backendType, width)
	printRow(w, "TARGET", target, width)
	printRow(w, "DETAILS", "No active remote state lock found. Safe to run Terraform/OpenTofu.", width)
	fmt.Fprintln(w, border)
}

// RenderBreakSuccess renders brutalist confirmation when a lock is released.
func RenderBreakSuccess(w io.Writer, lock *backend.LockInfo) {
	width := 80
	border := "+" + strings.Repeat("-", width-2) + "+"

	statusBadge := colorize(colorGreen+colorBold, "[SUCCESS] Lock released")

	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "|  %s\n", colorize(colorBold, "TF-UNLOCK :: STATE LOCK RELEASED"))
	fmt.Fprintln(w, border)
	printRow(w, "STATUS", statusBadge, width)
	printRow(w, "LOCK ID", lock.ID, width)
	printRow(w, "BACKEND", lock.BackendType, width)
	printRow(w, "TARGET", lock.Target, width)
	fmt.Fprintln(w, border)
}

// RenderAutoBlocked renders CI gate failure box.
func RenderAutoBlocked(w io.Writer, lock *backend.LockInfo, threshold time.Duration) {
	width := 80
	border := "+" + strings.Repeat("-", width-2) + "+"

	badge := colorize(colorRed+colorBold, "[BLOCKED] Active lock held by another process")

	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "|  %s\n", colorize(colorBold, "TF-UNLOCK :: CI AUTO GATE"))
	fmt.Fprintln(w, border)
	printRow(w, "RESULT", badge, width)
	printRow(w, "LOCK ID", lock.ID, width)
	if lock.Who != "" {
		printRow(w, "WHO", lock.Who, width)
	}
	printRow(w, "AGE", fmt.Sprintf("%s (threshold: %s)", safety.FormatDuration(lock.Age()), safety.FormatDuration(threshold)), width)
	printRow(w, "TARGET", lock.Target, width)
	printRow(w, "ACTION", "Exiting with code 1 to prevent remote state corruption.", width)
	fmt.Fprintln(w, border)
}

// RenderAutoUnlocked renders CI gate auto-break report.
func RenderAutoUnlocked(w io.Writer, lock *backend.LockInfo, threshold time.Duration) {
	width := 80
	border := "+" + strings.Repeat("-", width-2) + "+"

	badge := colorize(colorYellow+colorBold, "[AUTO-UNLOCKED] Stale lock broken automatically")

	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "|  %s\n", colorize(colorBold, "TF-UNLOCK :: CI AUTO GATE"))
	fmt.Fprintln(w, border)
	printRow(w, "RESULT", badge, width)
	printRow(w, "LOCK ID", lock.ID, width)
	printRow(w, "AGE", fmt.Sprintf("%s (stale threshold: %s)", safety.FormatDuration(lock.Age()), safety.FormatDuration(threshold)), width)
	printRow(w, "TARGET", lock.Target, width)
	printRow(w, "ACTION", "Stale lock cleared. CI pipeline unblocked and safe to proceed.", width)
	fmt.Fprintln(w, border)
}

func printRow(w io.Writer, label, value string, totalWidth int) {
	labelWidth := 12
	prefix := fmt.Sprintf("|  %-*s: ", labelWidth, label)
	fmt.Fprintf(w, "%s%s\n", prefix, value)
}
