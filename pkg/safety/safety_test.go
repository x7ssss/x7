package safety

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestVerifyStaleness(t *testing.T) {
	threshold := 30 * time.Minute

	// Object created 10 minutes ago (active, not stale)
	activeCreated := time.Now().Add(-10 * time.Minute)
	err := VerifyStaleness(activeCreated, threshold, false)
	if err == nil {
		t.Errorf("expected error for active object without force, got nil")
	}

	// Active object with force
	err = VerifyStaleness(activeCreated, threshold, true)
	if err != nil {
		t.Errorf("expected nil with force=true, got: %v", err)
	}

	// Object created 45 minutes ago (stale)
	staleCreated := time.Now().Add(-45 * time.Minute)
	err = VerifyStaleness(staleCreated, threshold, false)
	if err != nil {
		t.Errorf("expected nil for stale object, got: %v", err)
	}

	// Zero timestamp
	err = VerifyStaleness(time.Time{}, threshold, false)
	if err != nil {
		t.Errorf("expected nil for zero timestamp, got: %v", err)
	}
}

func TestVerifyLockID(t *testing.T) {
	// Matching ID
	if err := VerifyLockID("lock-123", "lock-123"); err != nil {
		t.Errorf("expected nil for matching lock ID, got: %v", err)
	}

	// Empty requested ID
	if err := VerifyLockID("lock-123", ""); err != nil {
		t.Errorf("expected nil for empty expected ID, got: %v", err)
	}

	// Mismatched ID
	if err := VerifyLockID("lock-123", "lock-456"); err == nil {
		t.Errorf("expected error for mismatched lock ID, got nil")
	}
}

func TestConfirmPrompt(t *testing.T) {
	// Force bypasses prompt
	ok, err := ConfirmPrompt(nil, nil, "Break lock?", true, false)
	if err != nil || !ok {
		t.Errorf("expected true, nil for force=true; got %v, %v", ok, err)
	}

	// Non-interactive bypasses prompt
	ok, err = ConfirmPrompt(nil, nil, "Break lock?", false, true)
	if err != nil || !ok {
		t.Errorf("expected true, nil for nonInteractive=true; got %v, %v", ok, err)
	}

	// User types "yes"
	in := strings.NewReader("yes\n")
	var out bytes.Buffer
	ok, err = ConfirmPrompt(in, &out, "Confirm action", false, false)
	if err != nil || !ok {
		t.Errorf("expected true, nil for 'yes'; got %v, %v", ok, err)
	}

	// User types "no"
	in = strings.NewReader("no\n")
	out.Reset()
	ok, err = ConfirmPrompt(in, &out, "Confirm action", false, false)
	if err != nil || ok {
		t.Errorf("expected false, nil for 'no'; got %v, %v", ok, err)
	}
}

func TestFormatDuration(t *testing.T) {
	d := 2*time.Hour + 15*time.Minute + 30*time.Second
	if got := FormatDuration(d); got != "2h 15m 30s" {
		t.Errorf("got %s, want 2h 15m 30s", got)
	}

	d2 := 45 * time.Second
	if got2 := FormatDuration(d2); got2 != "45s" {
		t.Errorf("got %s, want 45s", got2)
	}
}

func TestVerifyBlastRadiusLimit(t *testing.T) {
	if err := VerifyBlastRadiusLimit(5, 10, false); err != nil {
		t.Errorf("expected within limit to pass: %v", err)
	}
	if err := VerifyBlastRadiusLimit(15, 10, false); err == nil {
		t.Errorf("expected exceeding limit to fail")
	}
	if err := VerifyBlastRadiusLimit(15, 10, true); err != nil {
		t.Errorf("expected force to bypass limit: %v", err)
	}
}

func TestVerifyNamespaceSafety(t *testing.T) {
	if err := VerifyNamespaceSafety("kube-system", false); err == nil {
		t.Errorf("expected error protecting kube-system")
	}
	if err := VerifyNamespaceSafety("kube-system", true); err != nil {
		t.Errorf("expected force to bypass protection: %v", err)
	}
	if err := VerifyNamespaceSafety("ephemeral-pr-123", false); err != nil {
		t.Errorf("expected non-protected namespace to pass: %v", err)
	}
}
