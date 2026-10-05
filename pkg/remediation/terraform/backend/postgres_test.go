package backend

import (
	"strings"
	"testing"
)

func TestSanitizeConnStr(t *testing.T) {
	// URL format
	urlConn := "postgres://myuser:supersecret@db.example.com:5432/tfstate?sslmode=require"
	sanitizedURL := sanitizeConnStr(urlConn)
	if strings.Contains(sanitizedURL, "supersecret") {
		t.Errorf("password leaked in sanitized url: %s", sanitizedURL)
	}

	// Key-value format
	kvConn := "host=localhost port=5432 user=tf password=secretpass dbname=state"
	sanitizedKV := sanitizeConnStr(kvConn)
	if strings.Contains(sanitizedKV, "secretpass") {
		t.Errorf("password leaked in sanitized kv: %s", sanitizedKV)
	}
	if !strings.Contains(sanitizedKV, "password=REDACTED") {
		t.Errorf("expected password=REDACTED in sanitized kv: %s", sanitizedKV)
	}
}

func TestPostgresManager_Target(t *testing.T) {
	mgr, err := NewPostgresManager(PostgresConfig{
		ConnStr:    "postgres://user:pass@localhost:5432/tfstate",
		SchemaName: "my_schema",
	})
	if err != nil {
		t.Fatalf("NewPostgresManager failed: %v", err)
	}

	target := mgr.Target()
	if strings.Contains(target, "pass") {
		t.Errorf("password exposed in Target: %s", target)
	}
	if mgr.Type() != "postgres" {
		t.Errorf("got type %s, want postgres", mgr.Type())
	}
}
