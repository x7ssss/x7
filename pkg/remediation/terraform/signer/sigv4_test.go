package signer

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeriveSigningKey(t *testing.T) {
	// Known test vector from AWS SigV4 documentation:
	// Date: 20130524
	// Region: us-east-1
	// Service: s3
	// Secret: wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
	// Expected kSigning: 98f1c0338f76451633d5992181473ca5acaa54d649f403212f1f5a707fb613f8

	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830"
	region := "us-east-1"
	service := "iam"

	kSigning := deriveSigningKey(secret, date, region, service)
	gotHex := hex.EncodeToString(kSigning)
	expectedHex := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"

	if gotHex != expectedHex {
		t.Fatalf("deriveSigningKey failed: got %s, want %s", gotHex, expectedHex)
	}
}

func TestSignRequest(t *testing.T) {
	creds := &Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		SessionToken:    "SESSIONTOKEN123",
	}

	signer := NewSigner(creds)
	req, err := http.NewRequest("GET", "https://my-bucket.s3.us-east-1.amazonaws.com/test.tfstate.tflock", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	signTime, err := time.Parse(time.RFC3339, "2026-09-27T10:00:00Z")
	if err != nil {
		t.Fatalf("failed to parse test time: %v", err)
	}

	err = signer.Sign(req, nil, "s3", "us-east-1", signTime)
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260927/us-east-1/s3/aws4_request") {
		t.Errorf("unexpected Authorization header prefix: %s", auth)
	}

	if !strings.Contains(auth, "SignedHeaders=") {
		t.Errorf("Authorization header missing SignedHeaders: %s", auth)
	}

	if !strings.Contains(auth, "Signature=") {
		t.Errorf("Authorization header missing Signature: %s", auth)
	}

	if req.Header.Get("X-Amz-Date") != "20260927T100000Z" {
		t.Errorf("unexpected X-Amz-Date: %s", req.Header.Get("X-Amz-Date"))
	}

	if req.Header.Get("X-Amz-Security-Token") != "SESSIONTOKEN123" {
		t.Errorf("unexpected X-Amz-Security-Token: %s", req.Header.Get("X-Amz-Security-Token"))
	}

	expectedPayloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // sha256 of empty
	if req.Header.Get("X-Amz-Content-Sha256") != expectedPayloadHash {
		t.Errorf("unexpected X-Amz-Content-Sha256: %s", req.Header.Get("X-Amz-Content-Sha256"))
	}
}

func TestBuildCanonicalQuery(t *testing.T) {
	params := url.Values{}
	params.Add("version-id", "abc")
	params.Add("partNumber", "2")
	params.Add("partNumber", "1")
	params.Add("uploadId", "xyz")

	got := buildCanonicalQuery(params)
	// sorted order: partNumber=1&partNumber=2&uploadId=xyz&version-id=abc
	expected := "partNumber=1&partNumber=2&uploadId=xyz&version-id=abc"
	if got != expected {
		t.Errorf("buildCanonicalQuery failed: got %s, want %s", got, expected)
	}
}

func TestReadCredentialsFile(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials")

	content := `
[default]
aws_access_key_id = DEFAULT_KEY
aws_secret_access_key = DEFAULT_SECRET

[custom-profile]
aws_access_key_id = CUSTOM_KEY
aws_secret_access_key = CUSTOM_SECRET
aws_session_token = CUSTOM_TOKEN
`
	if err := os.WriteFile(credPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp credentials file: %v", err)
	}

	// Test default profile
	creds, err := readCredentialsFile(credPath)
	if err != nil {
		t.Fatalf("failed to read default profile: %v", err)
	}
	if creds.AccessKeyID != "DEFAULT_KEY" || creds.SecretAccessKey != "DEFAULT_SECRET" {
		t.Errorf("unexpected default creds: %+v", creds)
	}

	// Test custom profile via AWS_PROFILE
	os.Setenv("AWS_PROFILE", "custom-profile")
	defer os.Unsetenv("AWS_PROFILE")

	customCreds, err := readCredentialsFile(credPath)
	if err != nil {
		t.Fatalf("failed to read custom profile: %v", err)
	}
	if customCreds.AccessKeyID != "CUSTOM_KEY" || customCreds.SessionToken != "CUSTOM_TOKEN" {
		t.Errorf("unexpected custom creds: %+v", customCreds)
	}
}
