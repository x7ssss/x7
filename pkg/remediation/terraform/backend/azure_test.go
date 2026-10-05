package backend

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAzureManager_Inspect_Locked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("expected HEAD, got %s", r.Method)
		}
		if !strings.HasPrefix(r.URL.Path, "/tfstate/prod.tfstate") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("missing Authorization header")
		}

		w.Header().Set("x-ms-lease-status", "locked")
		w.Header().Set("x-ms-lease-state", "leased")
		w.Header().Set("x-ms-lease-duration", "infinite")
		w.Header().Set("Last-Modified", "Sun, 27 Sep 2026 08:30:00 GMT")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dummyKey := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	mgr := &AzureManager{
		AccountName:   "teststorage",
		ContainerName: "tfstate",
		BlobName:      "prod.tfstate",
		AccountKey:    dummyKey,
		Endpoint:      server.URL,
		client:        server.Client(),
	}

	lock, err := mgr.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if lock == nil {
		t.Fatalf("expected lock info, got nil")
	}

	if lock.BackendType != "azurerm" {
		t.Errorf("got backend type %s, want azurerm", lock.BackendType)
	}
	if !strings.Contains(lock.Info, "leased") {
		t.Errorf("expected leased in Info: %s", lock.Info)
	}
}

func TestAzureManager_Inspect_Unlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-ms-lease-status", "unlocked")
		w.Header().Set("x-ms-lease-state", "available")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dummyKey := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	mgr := &AzureManager{
		AccountName:   "teststorage",
		ContainerName: "tfstate",
		BlobName:      "prod.tfstate",
		AccountKey:    dummyKey,
		Endpoint:      server.URL,
		client:        server.Client(),
	}

	lock, err := mgr.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if lock != nil {
		t.Errorf("expected nil lock for unlocked blob, got %+v", lock)
	}
}

func TestAzureManager_Break_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Query().Get("comp") != "lease" {
			t.Errorf("expected comp=lease, got %s", r.URL.Query().Get("comp"))
		}
		if r.Header.Get("x-ms-lease-action") != "break" {
			t.Errorf("expected x-ms-lease-action: break, got %s", r.Header.Get("x-ms-lease-action"))
		}
		if r.Header.Get("x-ms-lease-break-period") != "0" {
			t.Errorf("expected x-ms-lease-break-period: 0, got %s", r.Header.Get("x-ms-lease-break-period"))
		}

		w.Header().Set("x-ms-lease-time", "0")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	dummyKey := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	mgr := &AzureManager{
		AccountName:   "teststorage",
		ContainerName: "tfstate",
		BlobName:      "prod.tfstate",
		AccountKey:    dummyKey,
		Endpoint:      server.URL,
		client:        server.Client(),
	}

	err := mgr.Break(context.Background(), "azure-blob-lease", false)
	if err != nil {
		t.Fatalf("Break failed: %v", err)
	}
}
