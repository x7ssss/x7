package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/x7ssss/x7/pkg/remediation/terraform/signer"
)

// S3NativeManager manages native S3 lockfiles (<key>.tflock) introduced in Terraform 1.10+.
type S3NativeManager struct {
	Bucket   string
	Key      string
	Region   string
	Endpoint string
	LockFile string
	lastETag string
	client   *http.Client
	signer   *signer.Signer
}

// S3NativeConfig holds parameters needed to initialize S3NativeManager.
type S3NativeConfig struct {
	Bucket   string
	Key      string
	Region   string
	Endpoint string
}

// NewS3NativeManager creates a new S3 native lockfile manager.
func NewS3NativeManager(cfg S3NativeConfig) (*S3NativeManager, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("bucket is required for S3 native backend")
	}
	if cfg.Key == "" {
		return nil, errors.New("key is required for S3 native backend")
	}

	region := cfg.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
		if region == "" {
			region = os.Getenv("AWS_DEFAULT_REGION")
		}
		if region == "" {
			region = "us-east-1"
		}
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		if envEndpoint := os.Getenv("AWS_ENDPOINT_URL_S3"); envEndpoint != "" {
			endpoint = envEndpoint
		} else if envEndpoint := os.Getenv("AWS_ENDPOINT_URL"); envEndpoint != "" {
			endpoint = envEndpoint
		}
	}

	cleanKey := strings.Trim(cfg.Key, "/")
	lockFile := cleanKey + ".tflock"

	creds, err := signer.ResolveCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve AWS credentials: %w", err)
	}

	return &S3NativeManager{
		Bucket:   strings.Trim(cfg.Bucket, "/"),
		Key:      cleanKey,
		Region:   region,
		Endpoint: strings.TrimRight(endpoint, "/"),
		LockFile: lockFile,
		client:   &http.Client{Timeout: 30 * time.Second},
		signer:   signer.NewSigner(creds),
	}, nil
}

func (s *S3NativeManager) Type() string {
	return "s3-native"
}

func (s *S3NativeManager) Target() string {
	return fmt.Sprintf("s3://%s/%s", s.Bucket, s.LockFile)
}

// SetHTTPClient allows overriding the default HTTP client (useful for tests/mocks).
func (s *S3NativeManager) SetHTTPClient(client *http.Client) {
	s.client = client
}

// SetLastETag sets the cached ETag for testing or manual overrides.
func (s *S3NativeManager) SetLastETag(etag string) {
	s.lastETag = etag
}

// objectURL builds the appropriate S3 URL depending on custom endpoint or standard AWS S3.
func (s *S3NativeManager) objectURL() (*url.URL, error) {
	if s.Endpoint != "" {
		// Custom endpoint (e.g. MinIO, LocalStack): use path style
		base := strings.TrimRight(s.Endpoint, "/")
		rawURL := fmt.Sprintf("%s/%s/%s", base, s.Bucket, s.LockFile)
		return url.Parse(rawURL)
	}

	// Standard AWS S3 virtual hosted style
	var host string
	if s.Region == "us-east-1" {
		host = fmt.Sprintf("%s.s3.amazonaws.com", s.Bucket)
	} else {
		host = fmt.Sprintf("%s.s3.%s.amazonaws.com", s.Bucket, s.Region)
	}
	rawURL := fmt.Sprintf("https://%s/%s", host, s.LockFile)
	return url.Parse(rawURL)
}

func (s *S3NativeManager) Inspect(ctx context.Context) (*LockInfo, error) {
	targetURL, err := s.objectURL()
	if err != nil {
		return nil, fmt.Errorf("failed to construct S3 URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	if err := s.signer.Sign(req, nil, "s3", s.Region, time.Now()); err != nil {
		return nil, fmt.Errorf("failed to sign S3 GET request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("S3 GET lockfile request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// 404: No lockfile exists
		return nil, nil
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("S3 GET lockfile returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	var lock LockInfo
	if err := json.Unmarshal(respBytes, &lock); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LockInfo from S3 lockfile: %w", err)
	}

	etag := strings.Trim(resp.Header.Get("ETag"), "\"")
	s.lastETag = etag
	lock.ETag = etag
	lock.BackendType = s.Type()
	lock.Target = s.Target()

	return &lock, nil
}

func (s *S3NativeManager) Break(ctx context.Context, lockID string, force bool) error {
	targetURL, err := s.objectURL()
	if err != nil {
		return fmt.Errorf("failed to construct S3 URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", targetURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Conditional delete using If-Match when ETag is known and not forced
	if !force && s.lastETag != "" {
		formattedETag := s.lastETag
		if !strings.HasPrefix(formattedETag, "\"") {
			formattedETag = fmt.Sprintf("\"%s\"", formattedETag)
		}
		req.Header.Set("If-Match", formattedETag)
	}

	if err := s.signer.Sign(req, nil, "s3", s.Region, time.Now()); err != nil {
		return fmt.Errorf("failed to sign S3 DELETE request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("S3 DELETE lockfile request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}

	if resp.StatusCode == http.StatusPreconditionFailed {
		return errors.New("state lock was modified concurrently (ETag precondition mismatch)")
	}

	respBytes, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("S3 DELETE lockfile returned HTTP %d: %s", resp.StatusCode, string(respBytes))
}
