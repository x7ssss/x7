package triage

import (
	"context"
)

// Subsystem represents a core infrastructure domain monitored by x7.
type Subsystem string

const (
	SubsystemK8s   Subsystem = "k8s"
	SubsystemDB    Subsystem = "db"
	SubsystemInfra Subsystem = "infra"
)

// Severity indicates the operational health status of a diagnostic check.
type Severity string

const (
	SeverityOK       Severity = "OK"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
	SeverityDeadlock Severity = "DEADLOCKED"
)

// RemediateFunc defines the function signature for automated or interactive remediation.
type RemediateFunc func(ctx context.Context, dryRun bool) error

// DiagnosticResult encapsulates findings from an engine inspection.
type DiagnosticResult struct {
	ID          string        `json:"id"`
	Subsystem   Subsystem     `json:"subsystem"`
	Target      string        `json:"target"`
	Severity    Severity      `json:"severity"`
	Summary     string        `json:"summary"`
	Details     string        `json:"details,omitempty"`
	Remediable  bool          `json:"remediable"`
	RemediateFn RemediateFunc `json:"-"`
}

// DoctorEngine represents an individual diagnostic engine.
type DoctorEngine interface {
	Name() string
	Subsystem() Subsystem
	Inspect(ctx context.Context) ([]DiagnosticResult, error)
}
