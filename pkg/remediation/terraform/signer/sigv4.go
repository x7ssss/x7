package signer

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	timeFormatISO8601 = "20060102T150405Z"
	dateFormatOnly    = "20060102"
	aws4Algorithm     = "AWS4-HMAC-SHA256"
)

// Credentials holds AWS authentication credentials.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// ResolveCredentials resolves AWS credentials from environment variables
// or standard AWS credentials file (~/.aws/credentials).
func ResolveCredentials() (*Credentials, error) {
	// 1. Check environment variables
	ak := os.Getenv("AWS_ACCESS_KEY_ID")
	if ak == "" {
		ak = os.Getenv("AWS_ACCESS_KEY")
	}
	sk := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if sk == "" {
		sk = os.Getenv("AWS_SECRET_KEY")
	}
	st := os.Getenv("AWS_SESSION_TOKEN")
	if st == "" {
		st = os.Getenv("AWS_SECURITY_TOKEN")
	}

	if ak != "" && sk != "" {
		return &Credentials{
			AccessKeyID:     ak,
			SecretAccessKey: sk,
			SessionToken:    st,
		}, nil
	}

	// 2. Check ~/.aws/credentials
	credFile := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if credFile == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			credFile = filepath.Join(home, ".aws", "credentials")
		}
	}

	if credFile != "" {
		if creds, err := readCredentialsFile(credFile); err == nil && creds != nil {
			return creds, nil
		}
	}

	return nil, errors.New("AWS credentials not found: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
}

// readCredentialsFile parses standard INI credentials file for the active profile.
func readCredentialsFile(filename string) (*Credentials, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	targetProfile := os.Getenv("AWS_PROFILE")
	if targetProfile == "" {
		targetProfile = "default"
	}

	scanner := bufio.NewScanner(file)
	currentSection := ""
	creds := &Credentials{}
	found := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[] ")
			continue
		}

		if strings.EqualFold(currentSection, targetProfile) {
			found = true
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch strings.ToLower(key) {
				case "aws_access_key_id":
					creds.AccessKeyID = val
				case "aws_secret_access_key":
					creds.SecretAccessKey = val
				case "aws_session_token":
					creds.SessionToken = val
				}
			}
		}
	}

	if found && creds.AccessKeyID != "" && creds.SecretAccessKey != "" {
		return creds, nil
	}

	return nil, fmt.Errorf("profile %q not found or incomplete in %s", targetProfile, filename)
}

// Signer signs HTTP requests using AWS Signature Version 4.
type Signer struct {
	creds *Credentials
}

// NewSigner creates a new SigV4 signer with the given credentials.
func NewSigner(creds *Credentials) *Signer {
	return &Signer{creds: creds}
}

// Sign signs the given HTTP request in-place.
func (s *Signer) Sign(req *http.Request, payload []byte, service, region string, t time.Time) error {
	if s.creds == nil || s.creds.AccessKeyID == "" || s.creds.SecretAccessKey == "" {
		return errors.New("cannot sign request: missing AWS access key ID or secret key")
	}

	utcTime := t.UTC()
	isoDate := utcTime.Format(timeFormatISO8601)
	dateOnly := utcTime.Format(dateFormatOnly)

	// Ensure Host header is present
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", isoDate)

	payloadHash := sha256Hex(payload)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	if s.creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.creds.SessionToken)
	}

	canonicalRequest, signedHeaders := buildCanonicalRequest(req, payloadHash)
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", dateOnly, region, service)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		aws4Algorithm,
		isoDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	)

	signingKey := deriveSigningKey(s.creds.SecretAccessKey, dateOnly, region, service)
	signature := hex.EncodeToString(hmacSha256(signingKey, []byte(stringToSign)))

	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		aws4Algorithm,
		s.creds.AccessKeyID,
		scope,
		signedHeaders,
		signature,
	)

	req.Header.Set("Authorization", authHeader)
	return nil
}

// buildCanonicalRequest constructs the canonical request string and signed headers list.
func buildCanonicalRequest(req *http.Request, payloadHash string) (string, string) {
	method := req.Method
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalURI = normalizeURIPath(canonicalURI)

	canonicalQuery := buildCanonicalQuery(req.URL.Query())

	// Canonical headers
	type headerEntry struct {
		lowerKey string
		value    string
	}

	var headers []headerEntry
	for k, vals := range req.Header {
		lower := strings.ToLower(strings.TrimSpace(k))
		cleanVals := make([]string, len(vals))
		for i, v := range vals {
			cleanVals[i] = strings.TrimSpace(v)
		}
		headers = append(headers, headerEntry{
			lowerKey: lower,
			value:    strings.Join(cleanVals, ","),
		})
	}

	// Sort headers alphabetically by lowerKey
	sort.Slice(headers, func(i, j int) bool {
		return headers[i].lowerKey < headers[j].lowerKey
	})

	var canonicalHeadersBuf bytes.Buffer
	var signedHeadersList []string
	for _, h := range headers {
		canonicalHeadersBuf.WriteString(h.lowerKey)
		canonicalHeadersBuf.WriteString(":")
		canonicalHeadersBuf.WriteString(h.value)
		canonicalHeadersBuf.WriteString("\n")
		signedHeadersList = append(signedHeadersList, h.lowerKey)
	}

	signedHeaders := strings.Join(signedHeadersList, ";")

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeadersBuf.String(),
		signedHeaders,
		payloadHash,
	)

	return canonicalRequest, signedHeaders
}

// normalizeURIPath ensures proper URI path formatting according to RFC 3986.
func normalizeURIPath(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	res := strings.Join(segments, "/")
	if !strings.HasPrefix(res, "/") {
		res = "/" + res
	}
	return res
}

// buildCanonicalQuery sorts and encodes query parameters.
func buildCanonicalQuery(params url.Values) string {
	if len(params) == 0 {
		return ""
	}

	type paramKV struct {
		key string
		val string
	}

	var pairs []paramKV
	for k, vs := range params {
		escapedKey := url.QueryEscape(k)
		for _, v := range vs {
			pairs = append(pairs, paramKV{
				key: escapedKey,
				val: url.QueryEscape(v),
			})
		}
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].val < pairs[j].val
		}
		return pairs[i].key < pairs[j].key
	})

	var parts []string
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s=%s", p.key, p.val))
	}

	return strings.Join(parts, "&")
}

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func hmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func deriveSigningKey(secretKey, dateOnly, region, service string) []byte {
	kDate := hmacSha256([]byte("AWS4"+secretKey), []byte(dateOnly))
	kRegion := hmacSha256(kDate, []byte(region))
	kService := hmacSha256(kRegion, []byte(service))
	kSigning := hmacSha256(kService, []byte("aws4_request"))
	return kSigning
}
