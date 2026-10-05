package codec

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"testing"
	"time"
)

func TestEncodeDecodeRoundtripLossless(t *testing.T) {
	now := time.Now().Truncate(time.Second).UTC()
	original := &ReleasePayload{
		Name:      "test-app",
		Version:   3,
		Namespace: "production",
		Info: &ReleaseInfo{
			FirstDeployed: now.Add(-2 * time.Hour),
			LastDeployed:  now.Add(-10 * time.Minute),
			Description:   "Upgrade in progress",
			Status:        StatusPendingUpgrade,
			Notes:         "Test deployment notes",
		},
		Manifest: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test-app\n",
		Labels: map[string]string{
			"app":     "test-app",
			"tier":    "backend",
			"version": "v1.2.3",
		},
		Chart:  json.RawMessage(`{"metadata":{"name":"test-chart","version":"0.1.0"}}`),
		Config: json.RawMessage(`{"replicaCount":3,"image":{"tag":"latest"}}`),
		Hooks:  json.RawMessage(`[{"name":"pre-install","kind":"Job"}]`),
	}

	// Also simulate raw unknown fields to verify lossless preservation
	rawJSONWithExtras := `{
		"name": "test-app",
		"version": 3,
		"namespace": "production",
		"custom_helm_field": "do_not_lose_me",
		"info": {
			"first_deployed": "` + now.Add(-2*time.Hour).Format(time.RFC3339) + `",
			"last_deployed": "` + now.Add(-10*time.Minute).Format(time.RFC3339) + `",
			"description": "Upgrade in progress",
			"status": "pending-upgrade",
			"notes": "Test deployment notes",
			"extra_info_metric": 42
		},
		"manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test-app\n",
		"labels": {"app": "test-app", "tier": "backend", "version": "v1.2.3"},
		"chart": {"metadata":{"name":"test-chart","version":"0.1.0"}},
		"config": {"replicaCount":3,"image":{"tag":"latest"}},
		"hooks": [{"name":"pre-install","kind":"Job"}]
	}`

	var loadedPayload ReleasePayload
	if err := json.Unmarshal([]byte(rawJSONWithExtras), &loadedPayload); err != nil {
		t.Fatalf("failed to unmarshal test JSON: %v", err)
	}

	encoded, err := EncodeForSecretData(&loadedPayload)
	if err != nil {
		t.Fatalf("EncodeForSecretData failed: %v", err)
	}

	// Verify the encoded data is valid base64
	decodedB64, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatalf("encoded output is not valid base64: %v", err)
	}

	// Verify gzip magic header 0x1f, 0x8b
	if len(decodedB64) < 2 || decodedB64[0] != 0x1f || decodedB64[1] != 0x8b {
		t.Fatalf("encoded output does not start with gzip magic bytes: got %x %x", decodedB64[0], decodedB64[1])
	}

	// Verify gzip decompression
	gzReader, err := gzip.NewReader(bytes.NewReader(decodedB64))
	if err != nil {
		t.Fatalf("gzip reader creation failed: %v", err)
	}
	decompressedJSON, err := io.ReadAll(gzReader)
	if err != nil {
		t.Fatalf("decompression failed: %v", err)
	}
	_ = gzReader.Close()

	// Verify unknown fields were preserved
	var checkMap map[string]interface{}
	if err := json.Unmarshal(decompressedJSON, &checkMap); err != nil {
		t.Fatalf("decompressed payload is not valid JSON: %v", err)
	}
	if checkMap["custom_helm_field"] != "do_not_lose_me" {
		t.Errorf("custom_helm_field was not preserved: got %v", checkMap["custom_helm_field"])
	}
	infoMap, ok := checkMap["info"].(map[string]interface{})
	if !ok || infoMap["extra_info_metric"] != float64(42) {
		t.Errorf("extra_info_metric was not preserved in info map: got %v", infoMap["extra_info_metric"])
	}

	// Round-trip through DecodeFromSecretData
	decodedPayload, err := DecodeFromSecretData(encoded)
	if err != nil {
		t.Fatalf("DecodeFromSecretData failed: %v", err)
	}

	if decodedPayload.Name != original.Name {
		t.Errorf("expected name %s, got %s", original.Name, decodedPayload.Name)
	}
	if decodedPayload.Version != original.Version {
		t.Errorf("expected version %d, got %d", original.Version, decodedPayload.Version)
	}
	if decodedPayload.Namespace != original.Namespace {
		t.Errorf("expected namespace %s, got %s", original.Namespace, decodedPayload.Namespace)
	}
	if decodedPayload.Info.Status != original.Info.Status {
		t.Errorf("expected status %s, got %s", original.Info.Status, decodedPayload.Info.Status)
	}
	if decodedPayload.Info.Description != original.Info.Description {
		t.Errorf("expected description %s, got %s", original.Info.Description, decodedPayload.Info.Description)
	}
	if decodedPayload.Manifest != original.Manifest {
		t.Errorf("manifest mismatch")
	}
	if !reflect.DeepEqual(decodedPayload.Labels, original.Labels) {
		t.Errorf("labels mismatch: got %v, want %v", decodedPayload.Labels, original.Labels)
	}
}

func TestGzipCompressionLevel9(t *testing.T) {
	// Large repetitive payload to test compression efficacy
	payload := &ReleasePayload{
		Name:      "large-app",
		Version:   1,
		Namespace: "default",
		Info: &ReleaseInfo{
			Status:      StatusPendingInstall,
			Description: "Initial installation",
		},
		Manifest: string(bytes.Repeat([]byte("apiVersion: v1\nkind: ConfigMap\ndata:\n  key: value\n---\n"), 500)),
	}

	encoded, err := EncodeForSecretData(payload)
	if err != nil {
		t.Fatalf("EncodeForSecretData failed: %v", err)
	}

	decodedB64, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	// Check gzip header flags: OS byte and compression flag
	// Byte 2 is compression method (8 for deflate)
	// Byte 8 is extra flags (XFL): 2 indicates maximum compression (level 9)
	if len(decodedB64) < 10 {
		t.Fatalf("compressed data too short")
	}
	if decodedB64[2] != 8 {
		t.Errorf("expected deflate compression method 8, got %d", decodedB64[2])
	}
	if decodedB64[8] != 2 {
		t.Errorf("expected gzip XFL=2 (maximum compression level 9), got %d", decodedB64[8])
	}

	// Verify compression ratio on repetitive data is substantial (> 80% reduction)
	rawJSON, _ := json.Marshal(payload)
	ratio := float64(len(decodedB64)) / float64(len(rawJSON))
	if ratio > 0.20 {
		t.Errorf("expected compression ratio < 0.20 for repetitive manifest, got %f", ratio)
	}
}

func TestDecodeErrorHandling(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte(""),
			wantErr: true,
		},
		{
			name:    "invalid base64",
			data:    []byte("!!not-valid-base64!!"),
			wantErr: true,
		},
		{
			name:    "valid base64 but not gzip",
			data:    []byte(base64.StdEncoding.EncodeToString([]byte("hello world plain text"))),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeFromSecretData(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeFromSecretData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSecretNameHelpers(t *testing.T) {
	name := SecretName("my-app", 4)
	expected := "sh.helm.release.v1.my-app.v4"
	if name != expected {
		t.Errorf("SecretName() = %v, want %v", name, expected)
	}

	parsedName, rev, ok := ParseSecretName(name)
	if !ok || parsedName != "my-app" || rev != 4 {
		t.Errorf("ParseSecretName() = (%v, %v, %v), want (my-app, 4, true)", parsedName, rev, ok)
	}

	// Invalid secret names
	invalid := []string{
		"not-helm-secret",
		"sh.helm.release.v1.",
		"sh.helm.release.v1.my-app",
		"sh.helm.release.v1.my-app.vx",
		"sh.helm.release.v1.my-app.v-1",
	}
	for _, inv := range invalid {
		_, _, ok := ParseSecretName(inv)
		if ok {
			t.Errorf("expected ParseSecretName(%s) to return false", inv)
		}
	}
}

func TestIsPending(t *testing.T) {
	if !IsPending("pending-install") {
		t.Errorf("expected pending-install to be pending")
	}
	if !IsPending("pending-upgrade") {
		t.Errorf("expected pending-upgrade to be pending")
	}
	if !IsPending("pending-rollback") {
		t.Errorf("expected pending-rollback to be pending")
	}
	if IsPending("deployed") {
		t.Errorf("expected deployed not to be pending")
	}
	if IsPending("failed") {
		t.Errorf("expected failed not to be pending")
	}
}
