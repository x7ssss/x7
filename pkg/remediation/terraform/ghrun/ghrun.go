// Package ghrun determines whether the GitHub Actions run that owns a Terraform
// lock has terminated, so a lock is only broken when its owner is provably dead.
package ghrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultAPIURL is the public GitHub REST API base URL.
const DefaultAPIURL = "https://api.github.com"

// State classifies a workflow run.
type State int

const (
	// Active means the run may still be holding the lock (queued, in_progress, ...).
	Active State = iota
	// Terminal means the run has ended and can no longer hold the lock.
	Terminal
)

// Run is the subset of the workflow-run payload we care about.
type Run struct {
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

// Classify maps a run's status/conclusion to Active or Terminal.
// Unknown states are treated as Active (fail safe).
func (r Run) Classify() State {
	switch strings.ToLower(r.Conclusion) {
	case "cancelled", "timed_out", "failure", "success", "skipped", "startup_failure", "stale":
		return Terminal
	}
	if strings.ToLower(r.Status) == "completed" {
		return Terminal
	}
	return Active
}

// Checker queries the GitHub API for workflow-run state.
type Checker struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// GetRun fetches the run identified by repo ("owner/name") and runID.
func (c *Checker) GetRun(ctx context.Context, repo, runID string) (*Run, error) {
	if repo == "" || runID == "" {
		return nil, errors.New("github repo and run id are required")
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = DefaultAPIURL
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/actions/runs/%s", base, repo, runID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read github API response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var run Run
	if err := json.Unmarshal(body, &run); err != nil {
		return nil, fmt.Errorf("failed to decode github run: %w", err)
	}
	return &run, nil
}
