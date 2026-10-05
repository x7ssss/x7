package detector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseStateFile_S3DynamoDB(t *testing.T) {
	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "terraform.tfstate")

	content := `{
		"version": 3,
		"serial": 1,
		"backend": {
			"type": "s3",
			"config": {
				"bucket": "my-tf-state",
				"key": "prod/terraform.tfstate",
				"region": "us-west-2",
				"dynamodb_table": "my-tf-locks"
			}
		}
	}`

	if err := os.WriteFile(stateFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test state file: %v", err)
	}

	cfg, err := ParseStateFile(stateFile)
	if err != nil {
		t.Fatalf("ParseStateFile failed: %v", err)
	}

	if cfg.Type != "s3" {
		t.Errorf("got type %s, want s3", cfg.Type)
	}

	if GetString(cfg.Config, "dynamodb_table") != "my-tf-locks" {
		t.Errorf("got dynamodb_table %s, want my-tf-locks", GetString(cfg.Config, "dynamodb_table"))
	}

	if GetBool(cfg.Config, "use_lockfile") {
		t.Errorf("expected use_lockfile to be false")
	}

	os.Setenv("AWS_ACCESS_KEY_ID", "TEST_KEY")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "TEST_SECRET")
	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")

	mgr, err := NewLockManager(cfg)
	if err != nil {
		t.Fatalf("NewLockManager failed: %v", err)
	}

	if mgr.Type() != "s3-dynamodb" {
		t.Errorf("got manager type %s, want s3-dynamodb", mgr.Type())
	}
}

func TestParseStateFile_S3Native(t *testing.T) {
	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "terraform.tfstate")

	content := `{
		"version": 3,
		"backend": {
			"type": "s3",
			"config": {
				"bucket": "my-tf-state-native",
				"key": "infra/terraform.tfstate",
				"region": "eu-central-1",
				"use_lockfile": "true"
			}
		}
	}`

	if err := os.WriteFile(stateFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test state file: %v", err)
	}

	cfg, err := ParseStateFile(stateFile)
	if err != nil {
		t.Fatalf("ParseStateFile failed: %v", err)
	}

	if !GetBool(cfg.Config, "use_lockfile") {
		t.Errorf("expected use_lockfile to be true")
	}

	os.Setenv("AWS_ACCESS_KEY_ID", "TEST_KEY")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "TEST_SECRET")
	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")

	mgr, err := NewLockManager(cfg)
	if err != nil {
		t.Fatalf("NewLockManager failed: %v", err)
	}

	if mgr.Type() != "s3-native" {
		t.Errorf("got manager type %s, want s3-native", mgr.Type())
	}
}

func TestParseStateFile_AzureRM(t *testing.T) {
	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "terraform.tfstate")

	content := `{
		"version": 3,
		"backend": {
			"type": "azurerm",
			"config": {
				"storage_account_name": "mytfstorage",
				"container_name": "tfstate",
				"key": "prod.terraform.tfstate"
			}
		}
	}`

	if err := os.WriteFile(stateFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test state file: %v", err)
	}

	cfg, err := ParseStateFile(stateFile)
	if err != nil {
		t.Fatalf("ParseStateFile failed: %v", err)
	}

	if cfg.Type != "azurerm" {
		t.Errorf("got type %s, want azurerm", cfg.Type)
	}

	mgr, err := NewLockManager(cfg)
	if err != nil {
		t.Fatalf("NewLockManager failed: %v", err)
	}

	if mgr.Type() != "azurerm" {
		t.Errorf("got manager type %s, want azurerm", mgr.Type())
	}
}

func TestParseStateFile_Postgres(t *testing.T) {
	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "terraform.tfstate")

	content := `{
		"version": 3,
		"backend": {
			"type": "pg",
			"config": {
				"conn_str": "postgres://user:pass@localhost:5432/tfstate?sslmode=disable",
				"schema_name": "custom_schema"
			}
		}
	}`

	if err := os.WriteFile(stateFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test state file: %v", err)
	}

	cfg, err := ParseStateFile(stateFile)
	if err != nil {
		t.Fatalf("ParseStateFile failed: %v", err)
	}

	if cfg.Type != "pg" {
		t.Errorf("got type %s, want pg", cfg.Type)
	}

	mgr, err := NewLockManager(cfg)
	if err != nil {
		t.Fatalf("NewLockManager failed: %v", err)
	}

	if mgr.Type() != "postgres" {
		t.Errorf("got manager type %s, want postgres", mgr.Type())
	}
}

func TestParseStateFile_Errors(t *testing.T) {
	// 1. Missing file
	_, err := ParseStateFile("non_existent_path.tfstate")
	if err == nil {
		t.Errorf("expected error for missing file, got nil")
	}

	// 2. Invalid JSON
	tempDir := t.TempDir()
	badJSON := filepath.Join(tempDir, "bad.tfstate")
	os.WriteFile(badJSON, []byte("{not json"), 0644)
	_, err = ParseStateFile(badJSON)
	if err == nil {
		t.Errorf("expected error for bad json, got nil")
	}

	// 3. Unsupported backend
	unsupported := &BackendConfig{
		Type: "consul",
	}
	_, err = NewLockManager(unsupported)
	if err == nil {
		t.Errorf("expected error for unsupported backend, got nil")
	}
}
