package db

import (
	"context"
	"fmt"
	"strconv"

	"github.com/x7ssss/x7/pkg/triage"
)

// PGXidEngine audits datfrozenxid age against the 2-billion transaction wraparound cliff.
type PGXidEngine struct{}

func NewPGXidEngine() *PGXidEngine {
	return &PGXidEngine{}
}

func (e *PGXidEngine) Name() string {
	return "db-pgxid"
}

func (e *PGXidEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemDB
}

func (e *PGXidEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	cfg := GetPGConfig()
	if cfg == nil {
		return []triage.DiagnosticResult{
			{
				ID:         "db-pgxid-unconfigured",
				Subsystem:  triage.SubsystemDB,
				Target:     "PostgreSQL Wraparound",
				Severity:   triage.SeverityOK,
				Summary:    "No PostgreSQL host configured via PGHOST or POSTGRES_DSN; skipped",
				Remediable: false,
			},
		}, nil
	}

	query := "SELECT datname, age(datfrozenxid)::text FROM pg_database WHERE datallowconn ORDER BY age(datfrozenxid) DESC;"
	rows, err := ExecutePGQuery(ctx, cfg, query)
	if err != nil {
		return nil, fmt.Errorf("failed to audit pg_database datfrozenxid age: %w", err)
	}

	results := make([]triage.DiagnosticResult, 0)

	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		dbName := row[0]
		age, parseErr := strconv.ParseInt(row[1], 10, 64)
		if parseErr != nil {
			continue
		}

		target := fmt.Sprintf("Database '%s' (%s:%s)", dbName, cfg.Host, cfg.Port)

		if age >= 1900000000 {
			targetDB := dbName
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("db-pgxid-cliff-%s", dbName),
				Subsystem:  triage.SubsystemDB,
				Target:     target,
				Severity:   triage.SeverityDeadlock,
				Summary:    fmt.Sprintf("datfrozenxid age is %d; 2-billion transaction wraparound cliff imminent", age),
				Details:    fmt.Sprintf("Database '%s' is within 100M transactions of forced shutdown to prevent data loss. Immediate VACUUM FREEZE required.", dbName),
				Remediable: true,
				RemediateFn: func(remCtx context.Context, dryRun bool) error {
					if dryRun {
						return nil
					}
					// Connect specifically to targetDB to execute VACUUM FREEZE
					targetCfg := *cfg
					targetCfg.Database = targetDB
					_, vacErr := ExecutePGQuery(remCtx, &targetCfg, "VACUUM FREEZE;")
					return vacErr
				},
			})
		} else if age >= 1500000000 {
			targetDB := dbName
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("db-pgxid-critical-%s", dbName),
				Subsystem:  triage.SubsystemDB,
				Target:     target,
				Severity:   triage.SeverityCritical,
				Summary:    fmt.Sprintf("datfrozenxid age is %d; approaching aggressive autovacuum threshold", age),
				Details:    fmt.Sprintf("Database '%s' age is %d. Autovacuum fails to keep pace with transaction generation.", dbName, age),
				Remediable: true,
				RemediateFn: func(remCtx context.Context, dryRun bool) error {
					if dryRun {
						return nil
					}
					targetCfg := *cfg
					targetCfg.Database = targetDB
					_, vacErr := ExecutePGQuery(remCtx, &targetCfg, "VACUUM FREEZE;")
					return vacErr
				},
			})
		} else if age >= 1000000000 {
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("db-pgxid-warning-%s", dbName),
				Subsystem:  triage.SubsystemDB,
				Target:     target,
				Severity:   triage.SeverityWarning,
				Summary:    fmt.Sprintf("datfrozenxid age is %d; past half-life of 2-billion limit", age),
				Details:    fmt.Sprintf("Database '%s' age exceeds 1,000,000,000 transactions.", dbName),
				Remediable: false,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "db-pgxid-nominal",
			Subsystem:  triage.SubsystemDB,
			Target:     fmt.Sprintf("PostgreSQL (%s:%s)", cfg.Host, cfg.Port),
			Severity:   triage.SeverityOK,
			Summary:    "datfrozenxid age nominal across all databases (< 1,000,000,000)",
			Remediable: false,
		})
	}

	return results, nil
}
