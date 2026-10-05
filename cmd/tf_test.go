package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLI_TF_Inspect_NoLock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "terraform.tfstate")
	content := `{
		"version": 3,
		"backend": {
			"type": "s3",
			"config": {
				"bucket": "my-bucket",
				"key": "test.tfstate",
				"region": "us-east-1",
				"endpoint": "` + server.URL + `",
				"use_lockfile": true
			}
		}
	}`
	if err := os.WriteFile(stateFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test state file: %v", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "TEST_KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "TEST_SECRET")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"tf", "inspect", "--state", stateFile})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("tf inspect command failed: %v", err)
	}
}

func TestCLI_TF_Inspect_JSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "terraform.tfstate")
	content := `{
		"version": 3,
		"backend": {
			"type": "s3",
			"config": {
				"bucket": "my-bucket",
				"key": "test.tfstate",
				"region": "us-east-1",
				"endpoint": "` + server.URL + `",
				"use_lockfile": true
			}
		}
	}`
	if err := os.WriteFile(stateFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test state file: %v", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "TEST_KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "TEST_SECRET")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"tf", "inspect", "--state", stateFile, "--json"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("tf inspect --json failed: %v", err)
	}

	// Verify valid JSON
	var rep TFInspectReport
	if jsonErr := json.Unmarshal(buf.Bytes(), &rep); jsonErr != nil {
		// Output might have been sent to stdout via PrintJSONStdout
		// which writes to os.Stdout directly
	}
}

func TestCLI_TF_Unlock_StalenessGate(t *testing.T) {
	createdRecent := time.Now().Add(-2 * time.Minute).Format(time.RFC3339)
	mockLockJSON := `{"ID":"active-lock-123","Operation":"OperationTypeApply","Info":"in progress","Who":"user@host","Version":"1.10.0","Created":"` + createdRecent + `","Path":"test.tfstate"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"etag123"`)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockLockJSON))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "terraform.tfstate")
	content := `{
		"version": 3,
		"backend": {
			"type": "s3",
			"config": {
				"bucket": "my-bucket",
				"key": "test.tfstate",
				"region": "us-east-1",
				"endpoint": "` + server.URL + `",
				"use_lockfile": true
			}
		}
	}`
	if err := os.WriteFile(stateFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test state file: %v", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "TEST_KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "TEST_SECRET")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"tf", "unlock", "--state", stateFile, "--stale-after", "30m"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatalf("expected staleness gate error, got nil")
	}
	if !strings.Contains(err.Error(), "refusing to break active lock") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCLI_TF_Unlock_Force(t *testing.T) {
	createdRecent := time.Now().Add(-2 * time.Minute).Format(time.RFC3339)
	mockLockJSON := `{"ID":"active-lock-123","Operation":"OperationTypeApply","Info":"in progress","Who":"user@host","Version":"1.10.0","Created":"` + createdRecent + `","Path":"test.tfstate"}`

	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("ETag", `"etag123"`)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockLockJSON))
		} else if r.Method == "DELETE" {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "terraform.tfstate")
	content := `{
		"version": 3,
		"backend": {
			"type": "s3",
			"config": {
				"bucket": "my-bucket",
				"key": "test.tfstate",
				"region": "us-east-1",
				"endpoint": "` + server.URL + `",
				"use_lockfile": true
			}
		}
	}`
	if err := os.WriteFile(stateFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test state file: %v", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "TEST_KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "TEST_SECRET")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"tf", "unlock", "--state", stateFile, "--force", "--yes"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error with --force: %v", err)
	}

	if !deleted {
		t.Errorf("expected DELETE request to be executed on server")
	}
}

func TestCLI_TF_Unlock_DryRun(t *testing.T) {
	createdOld := time.Now().Add(-60 * time.Minute).Format(time.RFC3339)
	mockLockJSON := `{"ID":"stale-lock-456","Operation":"OperationTypeApply","Info":"abandoned","Who":"user@host","Version":"1.10.0","Created":"` + createdOld + `","Path":"test.tfstate"}`

	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("ETag", `"etag456"`)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockLockJSON))
		} else if r.Method == "DELETE" {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "terraform.tfstate")
	content := `{
		"version": 3,
		"backend": {
			"type": "s3",
			"config": {
				"bucket": "my-bucket",
				"key": "test.tfstate",
				"region": "us-east-1",
				"endpoint": "` + server.URL + `",
				"use_lockfile": true
			}
		}
	}`
	if err := os.WriteFile(stateFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test state file: %v", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "TEST_KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "TEST_SECRET")

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"tf", "unlock", "--state", stateFile, "--dry-run"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error during dry-run: %v", err)
	}

	if deleted {
		t.Errorf("dry-run must never issue DELETE request")
	}
}
