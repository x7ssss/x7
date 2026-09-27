package triage

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormatter_FormatText(t *testing.T) {
	formatter := NewFormatter()
	results := []DiagnosticResult{
		{
			ID:        "k8s-test",
			Subsystem: SubsystemK8s,
			Target:    "Namespace 'staging'",
			Severity:  SeverityDeadlock,
			Summary:   "Namespace stuck in Terminating phase",
		},
		{
			ID:        "db-test",
			Subsystem: SubsystemDB,
			Target:    "PostgreSQL 'primary-01'",
			Severity:  SeverityOK,
			Summary:   "datfrozenxid age nominal",
		},
		{
			ID:        "infra-test",
			Subsystem: SubsystemInfra,
			Target:    "Terraform Lock 'lock-123'",
			Severity:  SeverityWarning,
			Summary:   "Lock held for 20 minutes",
		},
	}

	var buf bytes.Buffer
	formatter.FormatText(&buf, results)
	output := buf.String()

	if !strings.Contains(output, "[KUBERNETES]") {
		t.Errorf("missing [KUBERNETES] section")
	}
	if !strings.Contains(output, "[STORAGE & DATABASES]") {
		t.Errorf("missing [STORAGE & DATABASES] section")
	}
	if !strings.Contains(output, "[INFRASTRUCTURE & STATE]") {
		t.Errorf("missing [INFRASTRUCTURE & STATE] section")
	}
	if !strings.Contains(output, "Namespace 'staging' : DEADLOCKED") {
		t.Errorf("missing formatted line for namespace result")
	}
	if !strings.Contains(output, "VERDICT: 1 actionable production deadlocks detected.") {
		t.Errorf("incorrect verdict line: %s", output)
	}
}

func TestFormatter_FormatJSON(t *testing.T) {
	formatter := NewFormatter()
	results := []DiagnosticResult{
		{
			ID:        "k8s-test",
			Subsystem: SubsystemK8s,
			Target:    "Target",
			Severity:  SeverityOK,
			Summary:   "Summary",
		},
	}

	var buf bytes.Buffer
	err := formatter.FormatJSON(&buf, results)
	if err != nil {
		t.Fatalf("json format failed: %v", err)
	}
	if !strings.Contains(buf.String(), `"id": "k8s-test"`) {
		t.Errorf("unexpected json output: %s", buf.String())
	}
}
