package backend

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// AzureManager manages state locks stored as Azure Blob leases.
type AzureManager struct {
	AccountName   string
	ContainerName string
	BlobName      string
	AccountKey    string
	SASToken      string
	BearerToken   string
	Endpoint      string
	client        *http.Client
}

// AzureConfig holds parameters needed to initialize AzureManager.
type AzureConfig struct {
	AccountName   string
	ContainerName string
	BlobName      string
	AccountKey    string
	SASToken      string
	BearerToken   string
	Endpoint      string
}

// NewAzureManager creates a new Azure Blob lease manager.
func NewAzureManager(cfg AzureConfig) (*AzureManager, error) {
	account := cfg.AccountName
	if account == "" {
		account = os.Getenv("ARM_STORAGE_ACCOUNT")
		if account == "" {
			account = os.Getenv("AZURE_STORAGE_ACCOUNT")
		}
	}
	if account == "" {
		return nil, errors.New("storage_account_name is required for azurerm backend")
	}

	container := cfg.ContainerName
	if container == "" {
		return nil, errors.New("container_name is required for azurerm backend")
	}

	blobKey := cfg.BlobName
	if blobKey == "" {
		return nil, errors.New("key (blob name) is required for azurerm backend")
	}

	key := cfg.AccountKey
	if key == "" {
		key = os.Getenv("ARM_ACCESS_KEY")
		if key == "" {
			key = os.Getenv("AZURE_STORAGE_KEY")
			if key == "" {
				key = os.Getenv("AZURE_STORAGE_ACCOUNT_KEY")
			}
		}
	}

	sas := cfg.SASToken
	if sas == "" {
		sas = os.Getenv("ARM_SAS_TOKEN")
		if sas == "" {
			sas = os.Getenv("AZURE_STORAGE_SAS_TOKEN")
		}
	}

	bearer := cfg.BearerToken
	if bearer == "" {
		bearer = os.Getenv("AZURE_STORAGE_BEARER_TOKEN")
		if bearer == "" {
			bearer = os.Getenv("ARM_BEARER_TOKEN")
		}
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.blob.core.windows.net", account)
	}

	return &AzureManager{
		AccountName:   account,
		ContainerName: container,
		BlobName:      strings.TrimPrefix(blobKey, "/"),
		AccountKey:    key,
		SASToken:      strings.TrimPrefix(sas, "?"),
		BearerToken:   bearer,
		Endpoint:      strings.TrimRight(endpoint, "/"),
		client:        &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (a *AzureManager) Type() string {
	return "azurerm"
}

func (a *AzureManager) Target() string {
	return fmt.Sprintf("azurerm://%s/%s/%s", a.AccountName, a.ContainerName, a.BlobName)
}

// SetHTTPClient allows overriding the default HTTP client (useful for tests/mocks).
func (a *AzureManager) SetHTTPClient(client *http.Client) {
	a.client = client
}

// blobURL returns the request URL with optional SAS token appended.
func (a *AzureManager) blobURL(extraParams url.Values) string {
	raw := fmt.Sprintf("%s/%s/%s", a.Endpoint, a.ContainerName, a.BlobName)
	if len(extraParams) > 0 || a.SASToken != "" {
		vals := url.Values{}
		if a.SASToken != "" {
			parsed, _ := url.ParseQuery(a.SASToken)
			for k, v := range parsed {
				vals[k] = v
			}
		}
		for k, v := range extraParams {
			vals[k] = v
		}
		raw += "?" + vals.Encode()
	}
	return raw
}

// sign signs the HTTP request using Azure SharedKey or Bearer token if configured.
func (a *AzureManager) sign(req *http.Request, contentLength int64) error {
	now := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("x-ms-date", now)
	req.Header.Set("x-ms-version", "2023-11-03")

	if a.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.BearerToken)
		return nil
	}

	if a.SASToken != "" {
		// SAS query token already appended to URL
		return nil
	}

	if a.AccountKey == "" {
		return errors.New("azure authentication required: set ARM_ACCESS_KEY, ARM_SAS_TOKEN, or ARM_BEARER_TOKEN")
	}

	// Azure Blob Storage SharedKey authorization
	decodedKey, err := base64.StdEncoding.DecodeString(a.AccountKey)
	if err != nil {
		return fmt.Errorf("invalid base64 Azure account key: %w", err)
	}

	lenStr := ""
	if req.Method == "PUT" || req.Method == "POST" {
		lenStr = fmt.Sprintf("%d", contentLength)
	}

	canonicalHeaders := a.buildCanonicalHeaders(req)
	canonicalResource := a.buildCanonicalResource(req)

	stringToSign := fmt.Sprintf("%s\n\n\n%s\n\n%s\n\n\n\n\n\n\n%s%s",
		req.Method,
		lenStr,
		req.Header.Get("Content-Type"),
		canonicalHeaders,
		canonicalResource,
	)

	h := hmac.New(sha256.New, decodedKey)
	h.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(h.Sum(nil))

	req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s:%s", a.AccountName, sig))
	return nil
}

func (a *AzureManager) buildCanonicalHeaders(req *http.Request) string {
	type headerKV struct {
		k string
		v string
	}
	var msHeaders []headerKV
	for k, vs := range req.Header {
		lower := strings.ToLower(strings.TrimSpace(k))
		if strings.HasPrefix(lower, "x-ms-") {
			msHeaders = append(msHeaders, headerKV{
				k: lower,
				v: strings.Join(vs, ","),
			})
		}
	}

	sort.Slice(msHeaders, func(i, j int) bool {
		return msHeaders[i].k < msHeaders[j].k
	})

	var b strings.Builder
	for _, h := range msHeaders {
		b.WriteString(h.k)
		b.WriteString(":")
		b.WriteString(h.v)
		b.WriteString("\n")
	}
	return b.String()
}

func (a *AzureManager) buildCanonicalResource(req *http.Request) string {
	res := fmt.Sprintf("/%s/%s/%s", a.AccountName, a.ContainerName, a.BlobName)

	queryParams := req.URL.Query()
	if len(queryParams) == 0 {
		return res
	}

	type paramKV struct {
		k string
		v string
	}
	var pairs []paramKV
	for k, vs := range queryParams {
		lower := strings.ToLower(k)
		sort.Strings(vs)
		pairs = append(pairs, paramKV{
			k: lower,
			v: strings.Join(vs, ","),
		})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].k < pairs[j].k
	})

	var b strings.Builder
	b.WriteString(res)
	for _, p := range pairs {
		b.WriteString("\n")
		b.WriteString(p.k)
		b.WriteString(":")
		b.WriteString(p.v)
	}
	return b.String()
}

func (a *AzureManager) Inspect(ctx context.Context) (*LockInfo, error) {
	reqURL := a.blobURL(nil)
	req, err := http.NewRequestWithContext(ctx, "HEAD", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure HEAD request: %w", err)
	}

	if err := a.sign(req, 0); err != nil {
		return nil, fmt.Errorf("failed to sign Azure HEAD request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Azure HEAD request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Azure HEAD blob returned HTTP %d", resp.StatusCode)
	}

	leaseStatus := strings.ToLower(resp.Header.Get("x-ms-lease-status"))
	leaseState := strings.ToLower(resp.Header.Get("x-ms-lease-state"))
	leaseDuration := strings.ToLower(resp.Header.Get("x-ms-lease-duration"))

	if leaseStatus != "locked" && leaseState != "leased" {
		return nil, nil
	}

	// Active lease detected
	created := time.Now().UTC()
	if lastMod := resp.Header.Get("Last-Modified"); lastMod != "" {
		if t, err := http.ParseTime(lastMod); err == nil {
			created = t.UTC()
		}
	}

	// Check if Terraform lock info was stored in metadata
	lockID := "azure-blob-lease"
	var metaLock LockInfo
	metaInfo := resp.Header.Get("x-ms-meta-terraform_lock_info")
	if metaInfo == "" {
		metaInfo = resp.Header.Get("x-ms-meta-lock_info")
	}

	if metaInfo != "" {
		if err := json.Unmarshal([]byte(metaInfo), &metaLock); err == nil && metaLock.ID != "" {
			metaLock.BackendType = a.Type()
			metaLock.Target = a.Target()
			return &metaLock, nil
		}
	}

	lock := &LockInfo{
		ID:          lockID,
		Operation:   "Azure Blob Lease",
		Info:        fmt.Sprintf("Lease status: %s, state: %s, duration: %s", leaseStatus, leaseState, leaseDuration),
		Who:         "Azure Lease Holder",
		Created:     created,
		Path:        fmt.Sprintf("%s/%s", a.ContainerName, a.BlobName),
		BackendType: a.Type(),
		Target:      a.Target(),
	}

	return lock, nil
}

func (a *AzureManager) Break(ctx context.Context, lockID string, force bool) error {
	params := url.Values{}
	params.Set("comp", "lease")

	reqURL := a.blobURL(params)
	req, err := http.NewRequestWithContext(ctx, "PUT", reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure lease break request: %w", err)
	}

	req.Header.Set("x-ms-lease-action", "break")
	req.Header.Set("x-ms-lease-break-period", "0")
	req.Header.Set("Content-Length", "0")

	if err := a.sign(req, 0); err != nil {
		return fmt.Errorf("failed to sign Azure lease break request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("Azure lease break request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusConflict {
		// Conflict: No active lease was present
		return errors.New("no active lease found on target Azure blob")
	}

	respBytes, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("Azure lease break returned HTTP %d: %s", resp.StatusCode, string(respBytes))
}
