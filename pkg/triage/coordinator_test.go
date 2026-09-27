package triage

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type mockEngine struct {
	name      string
	subsystem Subsystem
	inspectFn func(ctx context.Context) ([]DiagnosticResult, error)
}

func (m *mockEngine) Name() string {
	return m.name
}

func (m *mockEngine) Subsystem() Subsystem {
	return m.subsystem
}

func (m *mockEngine) Inspect(ctx context.Context) ([]DiagnosticResult, error) {
	if m.inspectFn != nil {
		return m.inspectFn(ctx)
	}
	return []DiagnosticResult{
		{
			ID:        m.name + "-res",
			Subsystem: m.subsystem,
			Target:    m.name,
			Severity:  SeverityOK,
			Summary:   "nominal",
		},
	}, nil
}

func TestCoordinator_SubsystemFiltering(t *testing.T) {
	k8sEng := &mockEngine{name: "k8s-eng", subsystem: SubsystemK8s}
	dbEng := &mockEngine{name: "db-eng", subsystem: SubsystemDB}
	infraEng := &mockEngine{name: "infra-eng", subsystem: SubsystemInfra}

	coord := NewCoordinator(k8sEng, dbEng, infraEng)

	// Test k8s filter
	results, err := coord.Run(context.Background(), SubsystemK8s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for k8s filter, got %d", len(results))
	}
	if results[0].Subsystem != SubsystemK8s {
		t.Errorf("expected subsystem k8s, got %s", results[0].Subsystem)
	}

	// Test db and infra filter
	results, err = coord.Run(context.Background(), SubsystemDB, SubsystemInfra)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results for db+infra filter, got %d", len(results))
	}

	// Test all subsystems
	results, err = coord.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results when no filter provided, got %d", len(results))
	}
}

func TestCoordinator_ConcurrentFanOut(t *testing.T) {
	var activeGoroutines int64
	var maxObservedGoroutines int64
	var totalCompleted int64

	engineCount := 12
	engines := make([]DoctorEngine, engineCount)

	for i := 0; i < engineCount; i++ {
		engines[i] = &mockEngine{
			name:      "mock-concurrent",
			subsystem: SubsystemInfra,
			inspectFn: func(ctx context.Context) ([]DiagnosticResult, error) {
				current := atomic.AddInt64(&activeGoroutines, 1)
				for {
					max := atomic.LoadInt64(&maxObservedGoroutines)
					if current <= max || atomic.CompareAndSwapInt64(&maxObservedGoroutines, max, current) {
						break
					}
				}

				time.Sleep(50 * time.Millisecond)
				atomic.AddInt64(&activeGoroutines, -1)
				atomic.AddInt64(&totalCompleted, 1)

				return []DiagnosticResult{
					{
						ID:        "concurrent-ok",
						Subsystem: SubsystemInfra,
						Target:    "Target",
						Severity:  SeverityOK,
						Summary:   "Engine completed successfully",
					},
				}, nil
			},
		}
	}

	coord := NewCoordinator(engines...)
	results, err := coord.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if int(atomic.LoadInt64(&totalCompleted)) != engineCount {
		t.Errorf("expected %d completed engines, got %d", engineCount, totalCompleted)
	}

	if len(results) != engineCount {
		t.Errorf("expected %d results, got %d", engineCount, len(results))
	}

	maxConc := atomic.LoadInt64(&maxObservedGoroutines)
	if maxConc > 6 {
		t.Errorf("concurrency exceeded limit of 6: observed %d", maxConc)
	}
	if maxConc < 2 {
		t.Errorf("expected concurrent fan-out, observed max concurrency %d", maxConc)
	}
}

func TestCoordinator_TimeoutAndErrorIsolation(t *testing.T) {
	failingEng := &mockEngine{
		name:      "failing-eng",
		subsystem: SubsystemDB,
		inspectFn: func(ctx context.Context) ([]DiagnosticResult, error) {
			return nil, errors.New("connection refused to postgres:5432")
		},
	}

	slowEng := &mockEngine{
		name:      "slow-eng",
		subsystem: SubsystemK8s,
		inspectFn: func(ctx context.Context) ([]DiagnosticResult, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(15 * time.Second):
				return []DiagnosticResult{{ID: "slow-ok", Severity: SeverityOK}}, nil
			}
		},
	}

	healthyEng := &mockEngine{
		name:      "healthy-eng",
		subsystem: SubsystemInfra,
		inspectFn: func(ctx context.Context) ([]DiagnosticResult, error) {
			return []DiagnosticResult{
				{
					ID:        "healthy-ok",
					Subsystem: SubsystemInfra,
					Target:    "Healthy Target",
					Severity:  SeverityOK,
					Summary:   "Healthy engine passed",
				},
			}, nil
		},
	}

	coord := NewCoordinator(failingEng, healthyEng)
	results, err := coord.Run(context.Background())
	if err != nil {
		t.Fatalf("coordinator Run must not return error when engine fails: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results (1 warning from failure, 1 ok from healthy), got %d", len(results))
	}

	var foundWarning, foundOK bool
	for _, r := range results {
		if r.Severity == SeverityWarning && r.Target == "Engine 'failing-eng'" {
			foundWarning = true
		}
		if r.Severity == SeverityOK && r.Target == "Healthy Target" {
			foundOK = true
		}
	}

	if !foundWarning {
		t.Errorf("expected engine failure to be converted to SeverityWarning result")
	}
	if !foundOK {
		t.Errorf("expected healthy engine to complete successfully despite sibling failure")
	}

	// Verify slow engine with early-cancelled parent context simulates timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	coordSlow := NewCoordinator(slowEng, healthyEng)
	slowResults, slowErr := coordSlow.Run(ctx)
	if slowErr != nil {
		t.Fatalf("expected no run error on timeout: %v", slowErr)
	}

	var foundSlowTimeout bool
	for _, r := range slowResults {
		if r.Severity == SeverityWarning && r.Target == "Engine 'slow-eng'" {
			foundSlowTimeout = true
		}
	}
	if !foundSlowTimeout {
		t.Errorf("expected slow engine timeout to be captured as SeverityWarning")
	}
}
