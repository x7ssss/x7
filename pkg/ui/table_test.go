package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestTable_Render(t *testing.T) {
	table := NewTable(
		TableColumn{Title: "Subsystem", Width: 10},
		TableColumn{Title: "Target", Width: 20},
		TableColumn{Title: "Status", Width: 10},
	)

	table.AddRow("k8s", "Namespace 'prod'", "OK")
	table.AddRow("db", "PostgreSQL 'main'", "DEADLOCKED")

	var buf bytes.Buffer
	table.Render(&buf)
	output := buf.String()

	if !strings.Contains(output, "Subsystem") || !strings.Contains(output, "Target") || !strings.Contains(output, "Status") {
		t.Errorf("table headers missing from output: %s", output)
	}
	if !strings.Contains(output, "Namespace 'prod'") {
		t.Errorf("table row missing from output: %s", output)
	}
	if !strings.Contains(output, "DEADLOCKED") {
		t.Errorf("table cell missing from output: %s", output)
	}
}

func TestRenderCard(t *testing.T) {
	var buf bytes.Buffer
	entries := [][2]string{
		{"Version", "v1.0.0"},
		{"Platform", "linux/amd64"},
	}

	RenderCard(&buf, "Test System Card", entries)
	output := buf.String()

	if !strings.Contains(output, "TEST SYSTEM CARD") {
		t.Errorf("card title missing: %s", output)
	}
	if !strings.Contains(output, "Version") || !strings.Contains(output, "v1.0.0") {
		t.Errorf("card content missing: %s", output)
	}
}
