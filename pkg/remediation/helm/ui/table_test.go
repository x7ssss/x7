package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestTableRender(t *testing.T) {
	var buf bytes.Buffer
	tbl := NewTable("Release", "Namespace", "Revision", "Status")
	tbl.AddRow("redis", "default", "1", "pending-install")
	tbl.AddRow("nginx-ingress", "kube-system", "12", "pending-upgrade")
	tbl.Render(&buf)

	output := buf.String()
	if !strings.Contains(output, "RELEASE") {
		t.Errorf("expected RELEASE in output, got: %s", output)
	}
	if !strings.Contains(output, "pending-install") {
		t.Errorf("expected pending-install in output, got: %s", output)
	}
	if !strings.Contains(output, "nginx-ingress") {
		t.Errorf("expected nginx-ingress in output, got: %s", output)
	}
}

func TestKeyValueBlockRender(t *testing.T) {
	var buf bytes.Buffer
	entries := [][2]string{
		{"Release Name", "vault"},
		{"Status", "failed"},
		{"Stuck Duration", "45m"},
	}
	RenderKeyValueBlock(&buf, "Diagnosis Report", entries)

	output := buf.String()
	if !strings.Contains(output, "DIAGNOSIS REPORT") {
		t.Errorf("expected DIAGNOSIS REPORT in output, got: %s", output)
	}
	if !strings.Contains(output, "vault") {
		t.Errorf("expected vault in output, got: %s", output)
	}
}
