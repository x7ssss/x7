package locking

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
)

const (
	// DefaultLeaseDuration is the default TTL for a distributed lock (e.g. 50 minutes).
	DefaultLeaseDuration = 50 * time.Minute

	// LockConditionExpression ensures atomic mutual exclusion or lease expiry.
	LockConditionExpression = "attribute_not_exists(LockID) OR ExpiresAt < :now"
)

// DynamoLocker manages distributed mutex locks in DynamoDB for VPC teardowns.
type DynamoLocker struct {
	client    awsclient.DynamoDBClient
	tableName string
	log       logger.Logger
}

// NewDynamoLocker initializes a new DynamoLocker instance.
func NewDynamoLocker(client awsclient.DynamoDBClient, tableName string, log logger.Logger) *DynamoLocker {
	return &DynamoLocker{
		client:    client,
		tableName: tableName,
		log:       log,
	}
}

// BuildLockParams constructs the item, condition expression, and attribute values for DynamoDB PutItem.
func BuildLockParams(vpcID string, owner string, now time.Time, leaseDuration time.Duration) (
	item map[string]dynamodbtypes.AttributeValue,
	condition string,
	attrValues map[string]dynamodbtypes.AttributeValue,
) {
	nowUnix := now.Unix()
	expiresAtUnix := now.Add(leaseDuration).Unix()

	item = map[string]dynamodbtypes.AttributeValue{
		"LockID":     &dynamodbtypes.AttributeValueMemberS{Value: vpcID},
		"Owner":      &dynamodbtypes.AttributeValueMemberS{Value: owner},
		"ExpiresAt":  &dynamodbtypes.AttributeValueMemberN{Value: strconv.FormatInt(expiresAtUnix, 10)},
		"AcquiredAt": &dynamodbtypes.AttributeValueMemberN{Value: strconv.FormatInt(nowUnix, 10)},
	}

	condition = LockConditionExpression

	attrValues = map[string]dynamodbtypes.AttributeValue{
		":now": &dynamodbtypes.AttributeValueMemberN{Value: strconv.FormatInt(nowUnix, 10)},
	}

	return item, condition, attrValues
}

// AcquireLock attempts to acquire a distributed lease lock for the given VPC ID.
func (d *DynamoLocker) AcquireLock(ctx context.Context, vpcID string, owner string, leaseDuration time.Duration) error {
	if d == nil || d.client == nil || d.tableName == "" {
		return nil
	}

	if owner == "" {
		owner = resolveDefaultOwner()
	}

	now := time.Now()
	item, condition, attrValues := BuildLockParams(vpcID, owner, now, leaseDuration)

	d.log.Info("Acquiring distributed lock on DynamoDB table %s for VPC %s (Owner: %s, Lease: %v)...",
		d.tableName, vpcID, owner, leaseDuration)

	_, err := d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(d.tableName),
		Item:                      item,
		ConditionExpression:       aws.String(condition),
		ExpressionAttributeValues: attrValues,
	})

	if err != nil {
		if isConditionalCheckFailed(err) {
			return fmt.Errorf("distributed lock conflict: VPC %s is already locked on table %q by another active runner",
				vpcID, d.tableName)
		}
		return fmt.Errorf("failed to acquire distributed lock on table %s: %w", d.tableName, err)
	}

	d.log.Success("Distributed lock acquired successfully for VPC %s", vpcID)
	return nil
}

// ReleaseLock releases the distributed lock for the given VPC ID.
func (d *DynamoLocker) ReleaseLock(ctx context.Context, vpcID string) error {
	if d == nil || d.client == nil || d.tableName == "" {
		return nil
	}

	d.log.Info("Releasing distributed lock on DynamoDB table %s for VPC %s...", d.tableName, vpcID)

	_, err := d.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]dynamodbtypes.AttributeValue{
			"LockID": &dynamodbtypes.AttributeValueMemberS{Value: vpcID},
		},
	})
	if err != nil {
		d.log.Warn("Failed to cleanly delete lock item for VPC %s on table %s: %v", vpcID, d.tableName, err)
		return err
	}

	d.log.Success("Distributed lock released successfully for VPC %s", vpcID)
	return nil
}

func isConditionalCheckFailed(err error) bool {
	if err == nil {
		return false
	}

	var ccf *dynamodbtypes.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return true
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "ConditionalCheckFailedException" || code == "ConditionalCheckFailed"
	}

	return false
}

func resolveDefaultOwner() string {
	if runID := os.Getenv("GITHUB_RUN_ID"); runID != "" {
		repo := os.Getenv("GITHUB_REPOSITORY")
		attempt := os.Getenv("GITHUB_RUN_ATTEMPT")
		return fmt.Sprintf("github-actions://%s/runs/%s/attempt/%s", repo, runID, attempt)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}
	return fmt.Sprintf("host:%s/pid:%d", hostname, os.Getpid())
}
