package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/x7ssss/x7/pkg/remediation/terraform/signer"
)

func TestS3NativeManager_Inspect_ActiveLock(t *testing.T) {
	mockLockJSON := `{"ID":"s3-lock-999","Operation":"OperationTypeApply","Info":"running terraform","Who":"dev@laptop","Version":"1.10.0","Created":"2026-09-27T09:30:00Z","Path":"prod/state.tfstate"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "prod/state.tfstate.tflock") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("missing Authorization header")
		}

		w.Header().Set("ETag", `"mock-etag-12345"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockLockJSON))
	}))
	defer server.Close()

	mgr := &S3NativeManager{
		Bucket:   "my-bucket",
		Key:      "prod/state.tfstate",
		Region:   "us-east-1",
		Endpoint: server.URL,
		LockFile: "prod/state.tfstate.tflock",
		client:   server.Client(),
		signer: signer.NewSigner(&signer.Credentials{
			AccessKeyID:     "TESTAK",
			SecretAccessKey: "TESTSK",
		}),
	}

	lock, err := mgr.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if lock == nil {
		t.Fatalf("expected lock info, got nil")
	}

	if lock.ID != "s3-lock-999" {
		t.Errorf("got lock ID %s, want s3-lock-999", lock.ID)
	}
	if lock.ETag != "mock-etag-12345" {
		t.Errorf("got ETag %s, want mock-etag-12345", lock.ETag)
	}
	if lock.BackendType != "s3-native" {
		t.Errorf("got backend type %s, want s3-native", lock.BackendType)
	}
}

func TestS3NativeManager_Inspect_NoLock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	mgr := &S3NativeManager{
		Bucket:   "my-bucket",
		Key:      "prod/state.tfstate",
		Region:   "us-east-1",
		Endpoint: server.URL,
		LockFile: "prod/state.tfstate.tflock",
		client:   server.Client(),
		signer: signer.NewSigner(&signer.Credentials{
			AccessKeyID:     "TESTAK",
			SecretAccessKey: "TESTSK",
		}),
	}

	lock, err := mgr.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if lock != nil {
		t.Errorf("expected nil lock, got %+v", lock)
	}
}

func TestS3NativeManager_Break_Conditional(t *testing.T) {
	var receivedIfMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		receivedIfMatch = r.Header.Get("If-Match")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	mgr := &S3NativeManager{
		Bucket:   "my-bucket",
		Key:      "prod/state.tfstate",
		Region:   "us-east-1",
		Endpoint: server.URL,
		LockFile: "prod/state.tfstate.tflock",
		lastETag: "etag-abc-xyz",
		client:   server.Client(),
		signer: signer.NewSigner(&signer.Credentials{
			AccessKeyID:     "TESTAK",
			SecretAccessKey: "TESTSK",
		}),
	}

	err := mgr.Break(context.Background(), "s3-lock-999", false)
	if err != nil {
		t.Fatalf("Break failed: %v", err)
	}

	if receivedIfMatch != `"etag-abc-xyz"` {
		t.Errorf("expected If-Match header %q, got %q", `"etag-abc-xyz"`, receivedIfMatch)
	}
}

func TestS3NativeManager_Break_PreconditionFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
	}))
	defer server.Close()

	mgr := &S3NativeManager{
		Bucket:   "my-bucket",
		Key:      "prod/state.tfstate",
		Region:   "us-east-1",
		Endpoint: server.URL,
		LockFile: "prod/state.tfstate.tflock",
		lastETag: "etag-old",
		client:   server.Client(),
		signer: signer.NewSigner(&signer.Credentials{
			AccessKeyID:     "TESTAK",
			SecretAccessKey: "TESTSK",
		}),
	}

	err := mgr.Break(context.Background(), "s3-lock-999", false)
	if err == nil {
		t.Fatalf("expected error on 412, got nil")
	}

	if !strings.Contains(err.Error(), "ETag precondition mismatch") {
		t.Errorf("unexpected error message: %v", err)
	}
}
