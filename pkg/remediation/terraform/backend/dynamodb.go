package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/x7ssss/x7/pkg/remediation/terraform/signer"
)

// DynamoDBManager manages state locks stored in AWS DynamoDB tables.
type DynamoDBManager struct {
	TableName string
	Bucket    string
	Key       string
	Region    string
	Endpoint  string
	LockKey   string
	client    *http.Client
	signer    *signer.Signer
}

// DynamoDBConfig holds parameters needed to initialize DynamoDBManager.
type DynamoDBConfig struct {
	TableName string
	Bucket    string
	Key       string
	Region    string
	Endpoint  string
	LockKey   string
}

// NewDynamoDBManager creates a new DynamoDB lock manager.
func NewDynamoDBManager(cfg DynamoDBConfig) (*DynamoDBManager, error) {
	if cfg.TableName == "" {
		return nil, errors.New("dynamodb_table is required for DynamoDB backend")
	}

	region := cfg.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
		if region == "" {
			region = os.Getenv("AWS_DEFAULT_REGION")
		}
		if region == "" {
			region = "us-east-1"
		}
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		if envEndpoint := os.Getenv("AWS_ENDPOINT_URL_DYNAMODB"); envEndpoint != "" {
			endpoint = envEndpoint
		} else if envEndpoint := os.Getenv("AWS_ENDPOINT_URL"); envEndpoint != "" {
			endpoint = envEndpoint
		} else {
			endpoint = fmt.Sprintf("https://dynamodb.%s.amazonaws.com", region)
		}
	}

	lockKey := cfg.LockKey
	if lockKey == "" {
		cleanBucket := strings.Trim(cfg.Bucket, "/")
		cleanKey := strings.Trim(cfg.Key, "/")
		if cleanBucket != "" && cleanKey != "" {
			lockKey = fmt.Sprintf("%s/%s", cleanBucket, cleanKey)
		} else if cleanKey != "" {
			lockKey = cleanKey
		}
	}

	creds, err := signer.ResolveCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve AWS credentials: %w", err)
	}

	return &DynamoDBManager{
		TableName: cfg.TableName,
		Bucket:    cfg.Bucket,
		Key:       cfg.Key,
		Region:    region,
		Endpoint:  strings.TrimRight(endpoint, "/"),
		LockKey:   lockKey,
		client:    &http.Client{Timeout: 30 * time.Second},
		signer:    signer.NewSigner(creds),
	}, nil
}

func (d *DynamoDBManager) Type() string {
	return "s3-dynamodb"
}

func (d *DynamoDBManager) Target() string {
	return fmt.Sprintf("dynamodb://%s/%s", d.TableName, d.LockKey)
}

// SetHTTPClient allows overriding the default HTTP client (useful for tests/mocks).
func (d *DynamoDBManager) SetHTTPClient(client *http.Client) {
	d.client = client
}

// ddbStringAttr represents an S attribute in DynamoDB JSON.
type ddbStringAttr struct {
	S string `json:"S"`
}

type getItemRequest struct {
	TableName      string                   `json:"TableName"`
	Key            map[string]ddbStringAttr `json:"Key"`
	ConsistentRead bool                     `json:"ConsistentRead"`
}

type getItemResponse struct {
	Item map[string]ddbStringAttr `json:"Item"`
}

type deleteItemRequest struct {
	TableName                 string                   `json:"TableName"`
	Key                       map[string]ddbStringAttr `json:"Key"`
	ConditionExpression       string                   `json:"ConditionExpression,omitempty"`
	ExpressionAttributeValues map[string]ddbStringAttr `json:"ExpressionAttributeValues,omitempty"`
}

func (d *DynamoDBManager) Inspect(ctx context.Context) (*LockInfo, error) {
	reqBody := getItemRequest{
		TableName: d.TableName,
		Key: map[string]ddbStringAttr{
			"LockID": {S: d.LockKey},
		},
		ConsistentRead: true,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GetItem request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", d.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810.GetItem")

	if err := d.signer.Sign(req, payload, "dynamodb", d.Region, time.Now()); err != nil {
		return nil, fmt.Errorf("failed to sign DynamoDB request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DynamoDB GetItem request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DynamoDB response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DynamoDB GetItem returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	var ddbResp getItemResponse
	if err := json.Unmarshal(respBytes, &ddbResp); err != nil {
		return nil, fmt.Errorf("failed to decode DynamoDB GetItem response: %w", err)
	}

	infoAttr, ok := ddbResp.Item["Info"]
	if !ok || infoAttr.S == "" {
		// No active lock item found
		return nil, nil
	}

	var lock LockInfo
	if err := json.Unmarshal([]byte(infoAttr.S), &lock); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LockInfo from DynamoDB Item: %w", err)
	}

	lock.BackendType = d.Type()
	lock.Target = d.Target()
	return &lock, nil
}

// BuildDeleteCondition returns the DynamoDB conditional-delete expression. When an
// expected lock ID is supplied, the delete only succeeds if the stored Info
// payload still contains that ID, preventing deletion of a lock re-acquired by
// another runner between inspection and deletion.
func BuildDeleteCondition(expectedID string) (string, map[string]ddbStringAttr) {
	if expectedID == "" {
		return "attribute_exists(LockID)", nil
	}
	return "attribute_exists(LockID) AND contains(Info, :expectedID)", map[string]ddbStringAttr{
		":expectedID": {S: expectedID},
	}
}

func (d *DynamoDBManager) Break(ctx context.Context, lockID string, force bool) error {
	reqBody := deleteItemRequest{
		TableName: d.TableName,
		Key: map[string]ddbStringAttr{
			"LockID": {S: d.LockKey},
		},
	}

	// Use conditional delete unless forced
	if !force {
		reqBody.ConditionExpression, reqBody.ExpressionAttributeValues = BuildDeleteCondition(lockID)
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal DeleteItem request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", d.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810.DeleteItem")

	if err := d.signer.Sign(req, payload, "dynamodb", d.Region, time.Now()); err != nil {
		return fmt.Errorf("failed to sign DynamoDB request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("DynamoDB DeleteItem request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read DynamoDB response: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if strings.Contains(string(respBytes), "ConditionalCheckFailedException") {
		return errors.New("lock does not exist or has already been released")
	}

	return fmt.Errorf("DynamoDB DeleteItem returned HTTP %d: %s", resp.StatusCode, string(respBytes))
}
