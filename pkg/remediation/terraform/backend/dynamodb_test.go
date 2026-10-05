package backend

import (
	"context"
	"github.com/x7ssss/x7/pkg/remediation/terraform/signer"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDynamoDBManager_Inspect_ActiveLock(t *testing.T) {
	mockLockJSON := `{"ID":"lock-abc-123","Operation":"OperationTypeApply","Info":"applying terraform","Who":"ci@worker","Version":"1.9.0","Created":"2026-09-27T10:00:00Z","Path":"prod/state.tfstate"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.GetItem" {
			t.Errorf("unexpected target header: %s", r.Header.Get("X-Amz-Target"))
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("missing Authorization header")
		}

		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"Item": {
				"LockID": {"S": "my-bucket/prod/state.tfstate"},
				"Info": {"S": "` + strings.ReplaceAll(mockLockJSON, `"`, `\"`) + `"}
			}
		}`))
	}))
	defer server.Close()

	mgr := &DynamoDBManager{
		TableName: "test-table",
		Bucket:    "my-bucket",
		Key:       "prod/state.tfstate",
		Region:    "us-east-1",
		Endpoint:  server.URL,
		LockKey:   "my-bucket/prod/state.tfstate",
		client:    server.Client(),
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

	if lock.ID != "lock-abc-123" {
		t.Errorf("got lock ID %s, want lock-abc-123", lock.ID)
	}
	if lock.Who != "ci@worker" {
		t.Errorf("got Who %s, want ci@worker", lock.Who)
	}
	if lock.BackendType != "s3-dynamodb" {
		t.Errorf("got BackendType %s, want s3-dynamodb", lock.BackendType)
	}
}

func TestDynamoDBManager_Inspect_NoLock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	mgr := &DynamoDBManager{
		TableName: "test-table",
		Endpoint:  server.URL,
		LockKey:   "my-bucket/prod/state.tfstate",
		Region:    "us-east-1",
		client:    server.Client(),
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

func TestDynamoDBManager_Break_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.DeleteItem" {
			t.Errorf("unexpected target header: %s", r.Header.Get("X-Amz-Target"))
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "ConditionExpression") {
			t.Errorf("expected ConditionExpression in DeleteItem body")
		}

		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	mgr := &DynamoDBManager{
		TableName: "test-table",
		Endpoint:  server.URL,
		LockKey:   "my-bucket/prod/state.tfstate",
		Region:    "us-east-1",
		client:    server.Client(),
		signer: signer.NewSigner(&signer.Credentials{
			AccessKeyID:     "TESTAK",
			SecretAccessKey: "TESTSK",
		}),
	}

	err := mgr.Break(context.Background(), "lock-abc", false)
	if err != nil {
		t.Fatalf("Break failed: %v", err)
	}
}

func TestDynamoDBManager_Break_ConditionalFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"The conditional request failed"}`))
	}))
	defer server.Close()

	mgr := &DynamoDBManager{
		TableName: "test-table",
		Endpoint:  server.URL,
		LockKey:   "my-bucket/prod/state.tfstate",
		Region:    "us-east-1",
		client:    server.Client(),
		signer: signer.NewSigner(&signer.Credentials{
			AccessKeyID:     "TESTAK",
			SecretAccessKey: "TESTSK",
		}),
	}

	err := mgr.Break(context.Background(), "lock-abc", false)
	if err == nil {
		t.Fatalf("expected error on ConditionalCheckFailed, got nil")
	}
	if !strings.Contains(err.Error(), "already been released") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBuildDeleteCondition(t *testing.T) {
	expr, vals := BuildDeleteCondition("")
	if expr != "attribute_exists(LockID)" || vals != nil {
		t.Errorf("empty id: got %q %v", expr, vals)
	}
	expr, vals = BuildDeleteCondition("abc-123")
	if expr != "attribute_exists(LockID) AND contains(Info, :expectedID)" {
		t.Errorf("unexpected expression %q", expr)
	}
	if vals[":expectedID"].S != "abc-123" {
		t.Errorf("unexpected values %v", vals)
	}
}

func TestDynamoDBManager_Break_SendsConditionalExpression(t *testing.T) {
	tests := []struct {
		name      string
		force     bool
		wantCond  bool
		wantValue bool
	}{
		{"safe delete is conditional on lock ID", false, true, true},
		{"forced delete is unconditional", true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				body = string(b)
				w.Write([]byte(`{}`))
			}))
			defer server.Close()
			mgr := &DynamoDBManager{
				TableName: "t", Endpoint: server.URL, LockKey: "b/k", Region: "us-east-1",
				client: server.Client(),
				signer: signer.NewSigner(&signer.Credentials{AccessKeyID: "A", SecretAccessKey: "S"}),
			}
			if err := mgr.Break(context.Background(), "lock-abc", tt.force); err != nil {
				t.Fatal(err)
			}
			hasCond := strings.Contains(body, "attribute_exists(LockID) AND contains(Info, :expectedID)")
			hasVal := strings.Contains(body, `":expectedID":{"S":"lock-abc"}`)
			if hasCond != tt.wantCond || hasVal != tt.wantValue {
				t.Errorf("body = %s", body)
			}
		})
	}
}
