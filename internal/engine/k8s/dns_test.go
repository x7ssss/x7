package k8s

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/x7ssss/x7/pkg/triage"
)

func TestDNSEngine_Inspect(t *testing.T) {
	tempDir := t.TempDir()
	conntrackFile := filepath.Join(tempDir, "nf_conntrack")

	// Header and 2 CPUs (core 0 has 1 drop in hex, core 1 has 0)
	header := "entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop\n"
	cpu0 := "0000000a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000005 00000001 00000000 00000000\n"
	cpu1 := "0000000b 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000006 00000000 00000000 00000000\n"

	content := []byte(header + cpu0 + cpu1)
	if err := os.WriteFile(conntrackFile, content, 0644); err != nil {
		t.Fatalf("failed to write mock conntrack file: %v", err)
	}

	engine := &DNSEngine{
		conntrackPath: conntrackFile,
	}

	results, err := engine.Inspect(context.Background())
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected diagnostic results")
	}

	if results[0].Severity != triage.SeverityCritical {
		t.Errorf("expected SeverityCritical for conntrack insert_failed drops, got %s", results[0].Severity)
	}
}

func TestDNSEngine_Nominal(t *testing.T) {
	tempDir := t.TempDir()
	conntrackFile := filepath.Join(tempDir, "nf_conntrack")

	header := "entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop\n"
	cpu0 := "0000000a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000005 00000000 00000000 00000000\n"

	content := []byte(header + cpu0)
	if err := os.WriteFile(conntrackFile, content, 0644); err != nil {
		t.Fatalf("failed to write mock conntrack file: %v", err)
	}

	engine := &DNSEngine{
		conntrackPath: conntrackFile,
	}

	results, err := engine.Inspect(context.Background())
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if len(results) == 0 || results[0].Severity != triage.SeverityOK {
		t.Errorf("expected SeverityOK when insert_failed is 0, got %+v", results)
	}
}
