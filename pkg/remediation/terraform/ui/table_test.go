package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/x7ssss/x7/pkg/remediation/terraform/backend"
)

func TestRenderLockInfo(t *testing.T) {
	lock := &backend.LockInfo{
		ID:          "test-lock-123",
		Operation:   "OperationTypePlan",
		Info:        "terraform execution",
		Who:         "user@workstation",
		Version:     "1.9.0",
		Created:     time.Now().Add(-45 * time.Minute),
		Path:        "prod/terraform.tfstate",
		BackendType: "s3-dynamodb",
		Target:      "dynamodb://my-table/my-bucket/state.tfstate",
	}

	var buf bytes.Buffer
	RenderLockInfo(&buf, lock, 30*time.Minute)

	out := buf.String()
	if !strings.Contains(out, "test-lock-123") {
		t.Errorf("output missing lock ID: %s", out)
	}
	if !strings.Contains(out, "STALE") {
		t.Errorf("output missing STALE status: %s", out)
	}

	// Verify invariant: Strictly NO em dashes
	if strings.Contains(out, "\u2014") || strings.Contains(out, "\u2013") {
		t.Errorf("output contains em dash or en dash: %s", out)
	}
}

func TestRenderClean(t *testing.T) {
	var buf bytes.Buffer
	RenderClean(&buf, "s3-native", "s3://bucket/state.tfstate.tflock")

	out := buf.String()
	if !strings.Contains(out, "UNLOCKED - CLEAN") {
		t.Errorf("output missing clean badge: %s", out)
	}

	if strings.Contains(out, "\u2014") || strings.Contains(out, "\u2013") {
		t.Errorf("output contains em dash or en dash: %s", out)
	}
}

func TestRenderBreakSuccess(t *testing.T) {
	lock := &backend.LockInfo{
		ID:          "test-lock-break",
		BackendType: "azurerm",
		Target:      "azurerm://acc/cont/blob",
	}

	var buf bytes.Buffer
	RenderBreakSuccess(&buf, lock)

	out := buf.String()
	if !strings.Contains(out, "SUCCESS") {
		t.Errorf("output missing success status: %s", out)
	}

	if strings.Contains(out, "\u2014") || strings.Contains(out, "\u2013") {
		t.Errorf("output contains em dash or en dash: %s", out)
	}
}

func TestRenderAuto(t *testing.T) {
	lock := &backend.LockInfo{
		ID:      "test-lock-auto",
		Who:     "ci-agent",
		Created: time.Now().Add(-10 * time.Minute),
		Target:  "postgres://localhost",
	}

	var buf bytes.Buffer
	RenderAutoBlocked(&buf, lock, 1*time.Hour)
	outBlocked := buf.String()
	if !strings.Contains(outBlocked, "BLOCKED") {
		t.Errorf("output missing blocked status: %s", outBlocked)
	}

	buf.Reset()
	RenderAutoUnlocked(&buf, lock, 1*time.Hour)
	outUnlocked := buf.String()
	if !strings.Contains(outUnlocked, "AUTO-UNLOCKED") {
		t.Errorf("output missing auto-unlocked status: %s", outUnlocked)
	}
}
