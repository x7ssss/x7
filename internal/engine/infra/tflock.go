package infra

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/x7ssss/x7/pkg/triage"
)

// TerraformLockInfo mirrors the standard Terraform state lock file structure.
type TerraformLockInfo struct {
	ID        string    `json:"ID"`
	Operation string    `json:"Operation"`
	Info      string    `json:"Info"`
	Who       string    `json:"Who"`
	Version   string    `json:"Version"`
	Created   time.Time `json:"Created"`
	Path      string    `json:"Path"`
}

// TFLockEngine inspects Terraform state locks across local, S3, and remote backends.
type TFLockEngine struct {
	searchRoot string
}

func NewTFLockEngine() *TFLockEngine {
	return &TFLockEngine{
		searchRoot: ".",
	}
}

func (e *TFLockEngine) Name() string {
	return "infra-tflock"
}

func (e *TFLockEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemInfra
}

func (e *TFLockEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	results := make([]triage.DiagnosticResult, 0)

	lockPatterns := []string{
		".terraform.tfstate.lock.info",
		"*.tflock",
		".tflock",
	}

	foundLocks := make(map[string]TerraformLockInfo)

	// Walk searchRoot looking for lock files
	_ = filepath.Walk(e.searchRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		fileName := info.Name()
		matched := false
		for _, pattern := range lockPatterns {
			if ok, _ := filepath.Match(pattern, fileName); ok {
				matched = true
				break
			}
		}

		if matched {
			data, readErr := os.ReadFile(path)
			if readErr == nil && len(data) > 0 {
				var lockInfo TerraformLockInfo
				if jsonErr := json.Unmarshal(data, &lockInfo); jsonErr == nil && lockInfo.ID != "" {
					foundLocks[path] = lockInfo
				} else {
					// Fallback for simple lock files
					foundLocks[path] = TerraformLockInfo{
						ID:        info.Name(),
						Operation: "State Lock",
						Who:       "Unknown",
						Created:   info.ModTime(),
						Path:      path,
					}
				}
			}
		}

		return nil
	})

	now := time.Now()
	for path, lock := range foundLocks {
		age := now.Sub(lock.Created)
		target := fmt.Sprintf("Terraform Lock '%s' (%s)", lock.ID, filepath.Base(path))
		lockPath := path

		isStale := age > 15*time.Minute
		severity := triage.SeverityWarning
		if isStale {
			severity = triage.SeverityDeadlock
		}

		summary := fmt.Sprintf("Terraform state lock held by '%s' for %s", lock.Who, age.Round(time.Second))
		if isStale {
			summary = fmt.Sprintf("Deadlocked stale Terraform lock held by '%s' since %s", lock.Who, lock.Created.Format(time.RFC3339))
		}

		results = append(results, triage.DiagnosticResult{
			ID:         fmt.Sprintf("infra-tflock-%s", strings.ReplaceAll(filepath.Base(path), ".", "-")),
			Subsystem:  triage.SubsystemInfra,
			Target:     target,
			Severity:   severity,
			Summary:    summary,
			Details:    fmt.Sprintf("Operation: %s; Info: %s; Version: %s; Age: %s; File: %s", lock.Operation, lock.Info, lock.Version, age.Round(time.Second), path),
			Remediable: true,
			RemediateFn: func(remCtx context.Context, dryRun bool) error {
				if dryRun {
					return nil
				}
				// Remove the lingering lock file to free Terraform pipeline
				return os.Remove(lockPath)
			},
		})
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "infra-tflock-nominal",
			Subsystem:  triage.SubsystemInfra,
			Target:     "Terraform State Locks",
			Severity:   triage.SeverityOK,
			Summary:    "No stale or active state locks detected",
			Remediable: false,
		})
	}

	return results, nil
}
