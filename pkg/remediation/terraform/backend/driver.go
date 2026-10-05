package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LockInfo represents the unified Terraform/OpenTofu state lock schema.
// It maps directly to statemgr.LockInfo used by Terraform core.
type LockInfo struct {
	ID        string    `json:"ID"`
	Operation string    `json:"Operation"`
	Info      string    `json:"Info"`
	Who       string    `json:"Who"`
	Version   string    `json:"Version"`
	Created   time.Time `json:"Created"`
	Path      string    `json:"Path"`

	// Driver-specific metadata
	BackendType string            `json:"-"`
	Target      string            `json:"-"`
	ETag        string            `json:"-"`
	Extra       map[string]string `json:"-"`
}

// UnmarshalJSON implements custom JSON unmarshaling to handle various
// timestamp formats produced by different Terraform versions.
func (l *LockInfo) UnmarshalJSON(data []byte) error {
	type Alias LockInfo
	aux := &struct {
		CreatedRaw interface{} `json:"Created"`
		*Alias
	}{
		Alias: (*Alias)(l),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return fmt.Errorf("failed to parse lock JSON: %w", err)
	}

	if aux.CreatedRaw != nil {
		switch v := aux.CreatedRaw.(type) {
		case string:
			parsedTime, err := parseFlexTime(v)
			if err != nil {
				return fmt.Errorf("failed to parse lock Created time %q: %w", v, err)
			}
			l.Created = parsedTime
		case float64:
			l.Created = time.Unix(int64(v), 0).UTC()
		}
	}

	return nil
}

// parseFlexTime parses timestamps across RFC3339Nano, RFC3339, and ISO8601 variants.
func parseFlexTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unsupported timestamp format: %s", s)
}

// Age returns how long the lock has been active.
func (l *LockInfo) Age() time.Duration {
	if l.Created.IsZero() {
		return 0
	}
	return time.Since(l.Created)
}

// IsStale returns true if the lock age exceeds the given threshold.
func (l *LockInfo) IsStale(threshold time.Duration) bool {
	if l.Created.IsZero() {
		return false
	}
	return l.Age() >= threshold
}

// LockManager is the unified interface implemented by all remote backend drivers.
type LockManager interface {
	// Type returns the name of the backend driver (e.g. s3-dynamodb, s3-native, azurerm, postgres).
	Type() string

	// Target returns a human-readable identifier of the target resource.
	Target() string

	// Inspect retrieves the active lock information if present.
	// Returns nil, nil if the state is not currently locked.
	Inspect(ctx context.Context) (*LockInfo, error)

	// Break releases the lock. If force is true, it overrides safety checks.
	Break(ctx context.Context, lockID string, force bool) error
}
