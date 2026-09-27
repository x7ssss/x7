package k8s

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/x7ssss/x7/pkg/triage"
)

// DNSEngine inspects Linux conntrack stats for UDP DNS race packet drops.
type DNSEngine struct {
	conntrackPath string
}

func NewDNSEngine() *DNSEngine {
	return &DNSEngine{
		conntrackPath: "/proc/net/stat/nf_conntrack",
	}
}

func (e *DNSEngine) Name() string {
	return "k8s-dns"
}

func (e *DNSEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemK8s
}

func (e *DNSEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	file, err := os.Open(e.conntrackPath)
	if err != nil {
		// Non-Linux or system where conntrack module is not loaded / procfs not exposed
		return []triage.DiagnosticResult{
			{
				ID:         "k8s-dns-conntrack-nominal",
				Subsystem:  triage.SubsystemK8s,
				Target:     "Host nf_conntrack",
				Severity:   triage.SeverityOK,
				Summary:    "nf_conntrack stat file not accessible on host OS; skipped",
				Details:    fmt.Sprintf("Path '%s' could not be opened: %v", e.conntrackPath, err),
				Remediable: false,
			},
		}, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return []triage.DiagnosticResult{
			{
				ID:         "k8s-dns-conntrack-empty",
				Subsystem:  triage.SubsystemK8s,
				Target:     "Host nf_conntrack",
				Severity:   triage.SeverityOK,
				Summary:    "nf_conntrack stat file is empty",
				Remediable: false,
			},
		}, nil
	}

	headerLine := scanner.Text()
	headers := strings.Fields(headerLine)
	insertFailedCol := -1
	for i, h := range headers {
		if h == "insert_failed" {
			insertFailedCol = i
			break
		}
	}

	if insertFailedCol == -1 {
		return []triage.DiagnosticResult{
			{
				ID:         "k8s-dns-conntrack-header-missing",
				Subsystem:  triage.SubsystemK8s,
				Target:     "Host nf_conntrack",
				Severity:   triage.SeverityOK,
				Summary:    "Header insert_failed column not found in nf_conntrack stats",
				Remediable: false,
			},
		}, nil
	}

	var totalInsertFailed uint64
	lineCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if insertFailedCol < len(fields) {
			valStr := fields[insertFailedCol]
			// nf_conntrack stats are typically hexadecimal, fallback to base 10
			val, parseErr := strconv.ParseUint(valStr, 16, 64)
			if parseErr != nil {
				val, _ = strconv.ParseUint(valStr, 10, 64)
			}
			totalInsertFailed += val
			lineCount++
		}
	}

	if totalInsertFailed > 0 {
		return []triage.DiagnosticResult{
			{
				ID:         "k8s-dns-conntrack-drops",
				Subsystem:  triage.SubsystemK8s,
				Target:     "Linux Kernel nf_conntrack",
				Severity:   triage.SeverityCritical,
				Summary:    fmt.Sprintf("Detected %d nf_conntrack insert_failed drops (UDP DNS race drops)", totalInsertFailed),
				Details:    fmt.Sprintf("Across %d CPU cores, insert_failed reached %d. Common cause: glibc/musl concurrent A and AAAA DNS queries colliding on conntrack tuple insertion.", lineCount, totalInsertFailed),
				Remediable: false,
			},
		}, nil
	}

	return []triage.DiagnosticResult{
		{
			ID:         "k8s-dns-conntrack-ok",
			Subsystem:  triage.SubsystemK8s,
			Target:     "Linux Kernel nf_conntrack",
			Severity:   triage.SeverityOK,
			Summary:    "nf_conntrack DNS insert_failed drop count is 0 (nominal)",
			Remediable: false,
		},
	}, nil
}
