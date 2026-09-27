package db

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/x7ssss/x7/pkg/triage"
)

// ClickHousePartStat represents a row from system.parts aggregation.
type ClickHousePartStat struct {
	Database  string `json:"database"`
	Table     string `json:"table"`
	Partition string `json:"partition"`
	Parts     int64  `json:"parts"`
}

// ClickHouseEngine audits active MergeTree parts per partition against delay and throw thresholds.
type ClickHouseEngine struct{}

func NewClickHouseEngine() *ClickHouseEngine {
	return &ClickHouseEngine{}
}

func (e *ClickHouseEngine) Name() string {
	return "db-clickhouse"
}

func (e *ClickHouseEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemDB
}

func (e *ClickHouseEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	chHost := os.Getenv("CLICKHOUSE_HOST")
	if chHost == "" {
		chHost = os.Getenv("CH_HOST")
	}
	if chHost == "" {
		chURL := os.Getenv("CLICKHOUSE_URL")
		if chURL != "" {
			if u, err := url.Parse(chURL); err == nil {
				chHost = u.Host
			}
		}
	}

	if chHost == "" {
		return []triage.DiagnosticResult{
			{
				ID:         "db-clickhouse-unconfigured",
				Subsystem:  triage.SubsystemDB,
				Target:     "ClickHouse MergeTree",
				Severity:   triage.SeverityOK,
				Summary:    "No ClickHouse host configured via CLICKHOUSE_HOST; skipped",
				Remediable: false,
			},
		}, nil
	}

	baseURL := chHost
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	if !strings.Contains(baseURL, ":") || strings.HasSuffix(baseURL, "://") {
		baseURL = baseURL + ":8123"
	}

	query := "SELECT database, table, partition, count() AS parts FROM system.parts WHERE active = 1 GROUP BY database, table, partition FORMAT JSONEachRow;"
	reqURL := fmt.Sprintf("%s/?query=%s", baseURL, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create clickhouse request failed: %w", err)
	}

	user := os.Getenv("CLICKHOUSE_USER")
	password := os.Getenv("CLICKHOUSE_PASSWORD")
	if user != "" {
		req.SetBasicAuth(user, password)
	}

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse http query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("clickhouse returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	scanner := bufio.NewScanner(resp.Body)
	results := make([]triage.DiagnosticResult, 0)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var stat ClickHousePartStat
		if jsonErr := json.Unmarshal([]byte(line), &stat); jsonErr != nil {
			continue
		}

		target := fmt.Sprintf("Table '%s.%s' (partition %s)", stat.Database, stat.Table, stat.Partition)
		dbName := stat.Database
		tblName := stat.Table
		partID := stat.Partition

		if stat.Parts >= 300 {
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("db-ch-throw-%s-%s-%s", stat.Database, stat.Table, stat.Partition),
				Subsystem:  triage.SubsystemDB,
				Target:     target,
				Severity:   triage.SeverityDeadlock,
				Summary:    fmt.Sprintf("Partition has %d active parts; exceeds 300 parts-to-throw threshold", stat.Parts),
				Details:    fmt.Sprintf("ClickHouse throws 'Too many parts in all data parts in table' errors, halting all incoming mutations and inserts."),
				Remediable: true,
				RemediateFn: func(remCtx context.Context, dryRun bool) error {
					if dryRun {
						return nil
					}
					optQuery := fmt.Sprintf("OPTIMIZE TABLE %s.%s PARTITION ID '%s' FINAL;", dbName, tblName, partID)
					optURL := fmt.Sprintf("%s/?query=%s", baseURL, url.QueryEscape(optQuery))
					optReq, rErr := http.NewRequestWithContext(remCtx, http.MethodPost, optURL, nil)
					if rErr != nil {
						return rErr
					}
					if user != "" {
						optReq.SetBasicAuth(user, password)
					}
					optResp, oErr := client.Do(optReq)
					if oErr != nil {
						return oErr
					}
					defer optResp.Body.Close()
					return nil
				},
			})
		} else if stat.Parts >= 150 {
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("db-ch-delay-%s-%s-%s", stat.Database, stat.Table, stat.Partition),
				Subsystem:  triage.SubsystemDB,
				Target:     target,
				Severity:   triage.SeverityWarning,
				Summary:    fmt.Sprintf("Partition has %d active parts; exceeds 150 parts-to-delay threshold", stat.Parts),
				Details:    "ClickHouse delays inserts artificially to allow background merges to catch up.",
				Remediable: false,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "db-clickhouse-nominal",
			Subsystem:  triage.SubsystemDB,
			Target:     fmt.Sprintf("ClickHouse (%s)", baseURL),
			Severity:   triage.SeverityOK,
			Summary:    "Active MergeTree parts per partition nominal (< 150 across all partitions)",
			Remediable: false,
		})
	}

	return results, nil
}
