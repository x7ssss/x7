package infra

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/x7ssss/x7/pkg/triage"
)

func TestCgroupEngine_Inspect(t *testing.T) {
	tempDir := t.TempDir()
	psiFile := filepath.Join(tempDir, "memory")

	content := []byte("some avg10=55.40 avg60=30.12 avg300=10.05 total=1234567\nfull avg10=10.20 avg60=5.10 avg300=1.00 total=54321\n")
	if err := os.WriteFile(psiFile, content, 0644); err != nil {
		t.Fatalf("failed to write mock psi file: %v", err)
	}

	engine := &CgroupEngine{
		psiMemoryPath: psiFile,
	}

	results, err := engine.Inspect(context.Background())
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected diagnostic results")
	}

	if results[0].Severity != triage.SeverityDeadlock {
		t.Errorf("expected SeverityDeadlock for avg10 > 50, got %s", results[0].Severity)
	}
}

func TestCgroupEngine_Nominal(t *testing.T) {
	tempDir := t.TempDir()
	psiFile := filepath.Join(tempDir, "memory")

	content := []byte("some avg10=2.40 avg60=1.12 avg300=0.05 total=12345\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	if err := os.WriteFile(psiFile, content, 0644); err != nil {
		t.Fatalf("failed to write mock psi file: %v", err)
	}

	engine := &CgroupEngine{
		psiMemoryPath: psiFile,
	}

	results, err := engine.Inspect(context.Background())
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	if len(results) == 0 || results[0].Severity != triage.SeverityOK {
		t.Errorf("expected SeverityOK for low psi pressure, got %+v", results)
	}
}
