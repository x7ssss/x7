package triage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// Coordinator coordinates concurrent diagnostic runs across registered DoctorEngines.
type Coordinator struct {
	mu      sync.RWMutex
	engines []DoctorEngine
}

// NewCoordinator creates a new Coordinator initialized with optional engines.
func NewCoordinator(engines ...DoctorEngine) *Coordinator {
	c := &Coordinator{
		engines: make([]DoctorEngine, 0, len(engines)),
	}
	c.engines = append(c.engines, engines...)
	return c
}

// Register adds an engine to the coordinator registry in a thread-safe manner.
func (c *Coordinator) Register(engine DoctorEngine) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.engines = append(c.engines, engine)
}

// Engines returns a slice of currently registered engines.
func (c *Coordinator) Engines() []DoctorEngine {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]DoctorEngine, len(c.engines))
	copy(copied, c.engines)
	return copied
}

// Run executes inspections across registered engines with bounded concurrency.
// Each check is isolated with a 10-second timeout. Engine failures do not cancel siblings.
func (c *Coordinator) Run(ctx context.Context, subsystems ...Subsystem) ([]DiagnosticResult, error) {
	c.mu.RLock()
	allEngines := make([]DoctorEngine, len(c.engines))
	copy(allEngines, c.engines)
	c.mu.RUnlock()

	// Filter engines by requested subsystems if specified
	targetEngines := make([]DoctorEngine, 0, len(allEngines))
	if len(subsystems) == 0 {
		targetEngines = append(targetEngines, allEngines...)
	} else {
		filterMap := make(map[Subsystem]bool, len(subsystems))
		for _, s := range subsystems {
			filterMap[s] = true
		}
		for _, eng := range allEngines {
			if filterMap[eng.Subsystem()] {
				targetEngines = append(targetEngines, eng)
			}
		}
	}

	var resultsMu sync.Mutex
	var results []DiagnosticResult

	g, groupCtx := errgroup.WithContext(ctx)
	g.SetLimit(6)

	for _, eng := range targetEngines {
		currentEngine := eng
		g.Go(func() error {
			// Per-check hard isolation with 10-second timeout
			checkCtx, cancel := context.WithTimeout(groupCtx, 10*time.Second)
			defer cancel()

			type inspectResult struct {
				res []DiagnosticResult
				err error
			}

			ch := make(chan inspectResult, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						ch <- inspectResult{
							err: fmt.Errorf("engine panic: %v", r),
						}
					}
				}()
				res, err := currentEngine.Inspect(checkCtx)
				ch <- inspectResult{res: res, err: err}
			}()

			var res []DiagnosticResult
			var err error

			select {
			case <-checkCtx.Done():
				err = fmt.Errorf("timeout exceeded after 10s: %w", checkCtx.Err())
			case item := <-ch:
				res = item.res
				err = item.err
			}

			resultsMu.Lock()
			defer resultsMu.Unlock()

			if err != nil {
				// Engine failure must NOT cancel siblings; capture as SeverityWarning
				results = append(results, DiagnosticResult{
					ID:         fmt.Sprintf("%s-warning", currentEngine.Name()),
					Subsystem:  currentEngine.Subsystem(),
					Target:     fmt.Sprintf("Engine '%s'", currentEngine.Name()),
					Severity:   SeverityWarning,
					Summary:    fmt.Sprintf("Check execution failure: %v", err),
					Details:    err.Error(),
					Remediable: false,
				})
			} else {
				results = append(results, res...)
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}
