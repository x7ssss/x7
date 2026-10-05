package codec

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Helm release status constants.
const (
	StatusUnknown         = "unknown"
	StatusDeployed        = "deployed"
	StatusUninstalled     = "uninstalled"
	StatusSuperseded      = "superseded"
	StatusFailed          = "failed"
	StatusUninstalling    = "uninstalling"
	StatusPendingInstall  = "pending-install"
	StatusPendingUpgrade  = "pending-upgrade"
	StatusPendingRollback = "pending-rollback"
)

// Secret metadata prefix and type.
const (
	SecretPrefix = "sh.helm.release.v1."
	SecretType   = "helm.sh/release.v1"
)

var (
	magicGzip = []byte{0x1f, 0x8b}

	// ErrInvalidGzipHeader indicates the uncompressed payload lacks gzip magic bytes.
	ErrInvalidGzipHeader = errors.New("invalid gzip magic header")
	// ErrEmptyData indicates the secret release data is empty.
	ErrEmptyData = errors.New("empty release data")
)

// IsPending returns true if the status represents a transition state.
func IsPending(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case StatusPendingInstall, StatusPendingUpgrade, StatusPendingRollback:
		return true
	default:
		return false
	}
}

// SecretName generates the canonical Helm v3 secret name.
func SecretName(releaseName string, revision int) string {
	return fmt.Sprintf("%s%s.v%d", SecretPrefix, releaseName, revision)
}

// ParseSecretName extracts the release name and revision from a secret name.
func ParseSecretName(secretName string) (string, int, bool) {
	if !strings.HasPrefix(secretName, SecretPrefix) {
		return "", 0, false
	}
	trimmed := strings.TrimPrefix(secretName, SecretPrefix)
	lastDot := strings.LastIndex(trimmed, ".v")
	if lastDot == -1 {
		return "", 0, false
	}
	name := trimmed[:lastDot]
	revStr := trimmed[lastDot+2:]
	revision, err := strconv.Atoi(revStr)
	if err != nil || revision < 1 || name == "" {
		return "", 0, false
	}
	return name, revision, true
}

// ReleaseInfo holds the deployment status and timestamps.
type ReleaseInfo struct {
	FirstDeployed time.Time `json:"first_deployed,omitempty"`
	LastDeployed  time.Time `json:"last_deployed,omitempty"`
	Deleted       time.Time `json:"deleted,omitempty"`
	Description   string    `json:"description,omitempty"`
	Status        string    `json:"status,omitempty"`
	Notes         string    `json:"notes,omitempty"`

	rawFields map[string]json.RawMessage
}

// UnmarshalJSON unmarshals JSON while preserving unknown fields.
func (i *ReleaseInfo) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	i.rawFields = raw

	type Alias ReleaseInfo
	var aux Alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	i.FirstDeployed = aux.FirstDeployed
	i.LastDeployed = aux.LastDeployed
	i.Deleted = aux.Deleted
	i.Description = aux.Description
	i.Status = aux.Status
	i.Notes = aux.Notes
	return nil
}

// MarshalJSON marshals JSON while preserving original fields.
func (i *ReleaseInfo) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage)
	for k, v := range i.rawFields {
		out[k] = v
	}

	if !i.FirstDeployed.IsZero() {
		b, err := json.Marshal(i.FirstDeployed)
		if err != nil {
			return nil, err
		}
		out["first_deployed"] = b
	}
	if !i.LastDeployed.IsZero() {
		b, err := json.Marshal(i.LastDeployed)
		if err != nil {
			return nil, err
		}
		out["last_deployed"] = b
	}
	if !i.Deleted.IsZero() {
		b, err := json.Marshal(i.Deleted)
		if err != nil {
			return nil, err
		}
		out["deleted"] = b
	}
	if i.Description != "" {
		b, err := json.Marshal(i.Description)
		if err != nil {
			return nil, err
		}
		out["description"] = b
	}
	if i.Status != "" {
		b, err := json.Marshal(i.Status)
		if err != nil {
			return nil, err
		}
		out["status"] = b
	}
	if i.Notes != "" {
		b, err := json.Marshal(i.Notes)
		if err != nil {
			return nil, err
		}
		out["notes"] = b
	}

	return json.Marshal(out)
}

// ReleasePayload mirrors Helm v3 release data model with lossless round-trip support.
type ReleasePayload struct {
	Name      string            `json:"name,omitempty"`
	Version   int               `json:"version,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Info      *ReleaseInfo      `json:"info,omitempty"`
	Chart     json.RawMessage   `json:"chart,omitempty"`
	Config    json.RawMessage   `json:"config,omitempty"`
	Manifest  string            `json:"manifest,omitempty"`
	Hooks     json.RawMessage   `json:"hooks,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`

	rawFields map[string]json.RawMessage
}

// UnmarshalJSON preserves unrecognized fields for lossless serialization.
func (p *ReleasePayload) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.rawFields = raw

	type Alias ReleasePayload
	var aux Alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	p.Name = aux.Name
	p.Version = aux.Version
	p.Namespace = aux.Namespace
	p.Info = aux.Info
	p.Chart = aux.Chart
	p.Config = aux.Config
	p.Manifest = aux.Manifest
	p.Hooks = aux.Hooks
	p.Labels = aux.Labels
	return nil
}

// MarshalJSON serializes the payload while preserving raw unmapped properties.
func (p *ReleasePayload) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage)
	for k, v := range p.rawFields {
		out[k] = v
	}

	if p.Name != "" {
		b, err := json.Marshal(p.Name)
		if err != nil {
			return nil, err
		}
		out["name"] = b
	}
	if p.Version != 0 {
		b, err := json.Marshal(p.Version)
		if err != nil {
			return nil, err
		}
		out["version"] = b
	}
	if p.Namespace != "" {
		b, err := json.Marshal(p.Namespace)
		if err != nil {
			return nil, err
		}
		out["namespace"] = b
	}
	if p.Info != nil {
		b, err := json.Marshal(p.Info)
		if err != nil {
			return nil, err
		}
		out["info"] = b
	}
	if len(p.Chart) > 0 {
		out["chart"] = p.Chart
	}
	if len(p.Config) > 0 {
		out["config"] = p.Config
	}
	if p.Manifest != "" {
		b, err := json.Marshal(p.Manifest)
		if err != nil {
			return nil, err
		}
		out["manifest"] = b
	}
	if len(p.Hooks) > 0 {
		out["hooks"] = p.Hooks
	}
	if len(p.Labels) > 0 {
		b, err := json.Marshal(p.Labels)
		if err != nil {
			return nil, err
		}
		out["labels"] = b
	}

	return json.Marshal(out)
}

// DecodeFromSecretData decodes a Helm release secret data bytes into ReleasePayload.
// It supports both base64-encoded strings (as stored by Helm in secret.Data["release"])
// and raw gzip byte slices.
func DecodeFromSecretData(data []byte) (*ReleasePayload, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	trimmed := bytes.TrimSpace(data)
	var gzipBytes []byte

	// Check if data is already raw gzip or needs base64 decode
	if bytes.HasPrefix(trimmed, magicGzip) {
		gzipBytes = trimmed
	} else {
		// Attempt standard base64 decoding
		decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
		if err != nil {
			// Try URL-safe base64 decoding if standard fails
			var urlErr error
			decoded, urlErr = base64.URLEncoding.DecodeString(string(trimmed))
			if urlErr != nil {
				return nil, fmt.Errorf("base64 decode release data: %w", err)
			}
		}
		gzipBytes = decoded
	}

	if len(gzipBytes) < 2 || !bytes.HasPrefix(gzipBytes, magicGzip) {
		return nil, ErrInvalidGzipHeader
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(gzipBytes))
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzReader.Close()

	jsonBytes, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, fmt.Errorf("decompress gzip payload: %w", err)
	}

	var payload ReleasePayload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal release json: %w", err)
	}

	return &payload, nil
}

// EncodeForSecretData marshals a ReleasePayload to JSON, compresses with gzip level 9,
// encodes to base64 ASCII, and returns the byte slice ready for secret.Data["release"].
func EncodeForSecretData(payload *ReleasePayload) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("cannot encode nil release payload")
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal release payload: %w", err)
	}

	var buf bytes.Buffer
	// Level 9 (gzip.BestCompression) is non-negotiable for etcd 1MB ceiling
	gzWriter, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("create gzip writer level 9: %w", err)
	}

	if _, err := gzWriter.Write(jsonBytes); err != nil {
		return nil, fmt.Errorf("gzip compress release json: %w", err)
	}

	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("close gzip writer: %w", err)
	}

	b64String := base64.StdEncoding.EncodeToString(buf.Bytes())
	return []byte(b64String), nil
}
