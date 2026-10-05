package safety

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/x7ssss/x7/pkg/remediation/terraform/backend"
	"github.com/x7ssss/x7/pkg/remediation/terraform/ghrun"
)

type fakeLookup struct {
	run *ghrun.Run
	err error
}

func (f fakeLookup) GetRun(context.Context, string, string) (*ghrun.Run, error) {
	return f.run, f.err
}

func TestVerifyRunnerTerminated(t *testing.T) {
	tests := []struct {
		name    string
		lookup  fakeLookup
		runID   string
		force   bool
		wantErr string
	}{
		{"cancelled ok", fakeLookup{run: &ghrun.Run{Status: "completed", Conclusion: "cancelled"}}, "1", false, ""},
		{"timed_out ok", fakeLookup{run: &ghrun.Run{Status: "completed", Conclusion: "timed_out"}}, "1", false, ""},
		{"failure ok", fakeLookup{run: &ghrun.Run{Status: "completed", Conclusion: "failure"}}, "1", false, ""},
		{"in_progress refused", fakeLookup{run: &ghrun.Run{Status: "in_progress"}}, "1", false, "still active"},
		{"queued refused", fakeLookup{run: &ghrun.Run{Status: "queued"}}, "1", false, "still active"},
		{"force bypasses", fakeLookup{run: &ghrun.Run{Status: "in_progress"}}, "1", true, ""},
		{"no run id skips", fakeLookup{err: errors.New("unused")}, "", false, ""},
		{"lookup error fails closed", fakeLookup{err: errors.New("boom")}, "1", false, "could not verify"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyRunnerTerminated(context.Background(), tt.lookup, "o/r", tt.runID, tt.force)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyStaleness_Tolerance(t *testing.T) {
	tol := 30 * time.Minute
	tests := []struct {
		name    string
		age     time.Duration
		force   bool
		wantErr bool
	}{
		{"younger than tolerance rejected", 5 * time.Minute, false, true},
		{"just under tolerance rejected", tol - time.Minute, false, true},
		{"older than tolerance accepted", tol + time.Minute, false, false},
		{"force overrides", time.Minute, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lock := &backend.LockInfo{ID: "x", Created: time.Now().Add(-tt.age)}
			if err := VerifyStaleness(lock, tol, tt.force); (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
