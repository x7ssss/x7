package safety

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/x7ssss/x7/pkg/remediation/terraform/backend"
)

func TestVerifyStaleness(t *testing.T) {
	threshold := 30 * time.Minute

	// Lock created 10 minutes ago (active, not stale)
	activeLock := &backend.LockInfo{
		ID:      "lock-active",
		Created: time.Now().Add(-10 * time.Minute),
	}

	err := VerifyStaleness(activeLock, threshold, false)
	if err == nil {
		t.Errorf("expected error for active lock without force, got nil")
	}

	// Active lock with force
	err = VerifyStaleness(activeLock, threshold, true)
	if err != nil {
		t.Errorf("expected nil with force=true, got: %v", err)
	}

	// Lock created 45 minutes ago (stale)
	staleLock := &backend.LockInfo{
		ID:      "lock-stale",
		Created: time.Now().Add(-45 * time.Minute),
	}

	err = VerifyStaleness(staleLock, threshold, false)
	if err != nil {
		t.Errorf("expected nil for stale lock, got: %v", err)
	}
}

func TestVerifyLockID(t *testing.T) {
	lock := &backend.LockInfo{ID: "expected-123"}

	// Matching ID
	if err := VerifyLockID(lock, "expected-123"); err != nil {
		t.Errorf("expected nil for matching lock ID, got: %v", err)
	}

	// Empty requested ID (should skip check)
	if err := VerifyLockID(lock, ""); err != nil {
		t.Errorf("expected nil for empty requested ID, got: %v", err)
	}

	// Mismatched ID
	if err := VerifyLockID(lock, "different-456"); err == nil {
		t.Errorf("expected error for mismatched lock ID, got nil")
	}
}

func TestConfirmBreak(t *testing.T) {
	// Force bypasses prompt
	ok, err := ConfirmBreak(nil, nil, "lock-1", true, false)
	if err != nil || !ok {
		t.Errorf("expected true, nil for force=true; got %v, %v", ok, err)
	}

	// Non-interactive bypasses prompt
	ok, err = ConfirmBreak(nil, nil, "lock-1", false, true)
	if err != nil || !ok {
		t.Errorf("expected true, nil for nonInteractive=true; got %v, %v", ok, err)
	}

	// User types "yes"
	in := strings.NewReader("yes\n")
	var out bytes.Buffer
	ok, err = ConfirmBreak(in, &out, "lock-1", false, false)
	if err != nil || !ok {
		t.Errorf("expected true, nil for 'yes'; got %v, %v", ok, err)
	}
	if !strings.Contains(out.String(), "Are you sure you want to break lock lock-1? (yes/no): ") {
		t.Errorf("prompt not printed as expected: %s", out.String())
	}

	// User types "no"
	in = strings.NewReader("no\n")
	out.Reset()
	ok, err = ConfirmBreak(in, &out, "lock-1", false, false)
	if err != nil || ok {
		t.Errorf("expected false, nil for 'no'; got %v, %v", ok, err)
	}
}

func TestFormatDuration(t *testing.T) {
	d := 2*time.Hour + 15*time.Minute + 30*time.Second
	got := FormatDuration(d)
	if got != "2h 15m 30s" {
		t.Errorf("got %s, want 2h 15m 30s", got)
	}

	d2 := 45 * time.Second
	got2 := FormatDuration(d2)
	if got2 != "45s" {
		t.Errorf("got %s, want 45s", got2)
	}
}
