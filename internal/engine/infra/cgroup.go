package infra

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/x7ssss/x7/pkg/triage"
)

// PSIMetrics captures Linux Pressure Stall Information metrics for a line.
type PSIMetrics struct {
	Type   string
	Avg10  float64
	Avg60  float64
	Avg300 float64
	Total  uint64
}

// CgroupEngine monitors Linux cgroup v2 PSI memory pressure for direct reclaim stalls.
type CgroupEngine struct {
	psiMemoryPath string
}

func NewCgroupEngine() *CgroupEngine {
	return &CgroupEngine{
		psiMemoryPath: "/proc/pressure/memory",
	}
}

func (e *CgroupEngine) Name() string {
	return "infra-cgroup"
}

func (e *CgroupEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemInfra
}

func parsePSILine(line string) *PSIMetrics {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}
	m := &PSIMetrics{Type: fields[0]}
	for _, f := range fields[1:] {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "avg10":
			m.Avg10, _ = strconv.ParseFloat(kv[1], 64)
		case "avg60":
			m.Avg60, _ = strconv.ParseFloat(kv[1], 64)
		case "avg300":
			m.Avg300, _ = strconv.ParseFloat(kv[1], 64)
		case "total":
			m.Total, _ = strconv.ParseUint(kv[1], 10, 64)
		}
	}
	return m
}

func (e *CgroupEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	file, err := os.Open(e.psiMemoryPath)
	if err != nil {
		return []triage.DiagnosticResult{
			{
				ID:         "infra-cgroup-psi-nominal",
				Subsystem:  triage.SubsystemInfra,
				Target:     "Linux cgroup v2 PSI",
				Severity:   triage.SeverityOK,
				Summary:    "cgroup v2 PSI memory pressure not present on host OS; skipped",
				Details:    fmt.Sprintf("Failed to open %s: %v", e.psiMemoryPath, err),
				Remediable: false,
			},
		}, nil
	}
	defer file.Close()

	var somePSI, fullPSI *PSIMetrics
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "some") {
			somePSI = parsePSILine(line)
		} else if strings.HasPrefix(line, "full") {
			fullPSI = parsePSILine(line)
		}
	}

	results := make([]triage.DiagnosticResult, 0)
	target := "cgroup v2 memory.pressure"

	if fullPSI != nil && (fullPSI.Avg10 >= 50.0 || fullPSI.Avg60 >= 40.0) {
		results = append(results, triage.DiagnosticResult{
			ID:         "infra-cgroup-psi-full-critical",
			Subsystem:  triage.SubsystemInfra,
			Target:     target,
			Severity:   triage.SeverityCritical,
			Summary:    fmt.Sprintf("Severe memory PSI stall detected: full avg10=%.2f%%, avg60=%.2f%%", fullPSI.Avg10, fullPSI.Avg60),
			Details:    "All tasks in cgroup are stalled waiting for memory. Direct reclaim thrashing and OOM kills imminent.",
			Remediable: false,
		})
	} else if somePSI != nil && somePSI.Avg10 >= 50.0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "infra-cgroup-psi-some-deadlock",
			Subsystem:  triage.SubsystemInfra,
			Target:     target,
			Severity:   triage.SeverityDeadlock,
			Summary:    fmt.Sprintf("High direct reclaim stalls: some avg10=%.2f%%", somePSI.Avg10),
			Details:    "Substantial CPU time lost to synchronous direct memory reclaim and page cache thrashing.",
			Remediable: false,
		})
	} else if somePSI != nil && somePSI.Avg10 >= 25.0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "infra-cgroup-psi-warning",
			Subsystem:  triage.SubsystemInfra,
			Target:     target,
			Severity:   triage.SeverityWarning,
			Summary:    fmt.Sprintf("Elevated memory PSI pressure: some avg10=%.2f%%", somePSI.Avg10),
			Details:    "Processes are experiencing noticeable direct reclaim pauses.",
			Remediable: false,
		})
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "infra-cgroup-psi-ok",
			Subsystem:  triage.SubsystemInfra,
			Target:     target,
			Severity:   triage.SeverityOK,
			Summary:    "cgroup v2 memory PSI stall ratios within nominal thresholds (< 25.0%)",
			Remediable: false,
		})
	}

	return results, nil
}
