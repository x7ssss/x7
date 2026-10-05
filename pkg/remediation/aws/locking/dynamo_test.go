package locking

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
)

type mockDynamoClient struct {
	awsclient.DynamoDBClient
	putItemFn    func(ctx context.Context, params *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
	deleteItemFn func(ctx context.Context, params *dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error)

	lastPutInput    *dynamodb.PutItemInput
	lastDeleteInput *dynamodb.DeleteItemInput
}

func (m *mockDynamoClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	m.lastPutInput = params
	if m.putItemFn != nil {
		return m.putItemFn(ctx, params)
	}
	return &dynamodb.PutItemOutput{}, nil
}

func (m *mockDynamoClient) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	m.lastDeleteInput = params
	if m.deleteItemFn != nil {
		return m.deleteItemFn(ctx, params)
	}
	return &dynamodb.DeleteItemOutput{}, nil
}

func TestBuildLockParams(t *testing.T) {
	now := time.Unix(1700000000, 0)
	lease := 30 * time.Minute
	vpcID := "vpc-0123456789abcdef0"
	owner := "github-runner-42"

	item, condition, attrValues := BuildLockParams(vpcID, owner, now, lease)

	// Check condition
	if condition != "attribute_not_exists(LockID) OR ExpiresAt < :now" {
		t.Errorf("unexpected condition expression: %s", condition)
	}

	// Check item attributes
	lockIDVal, ok := item["LockID"].(*dynamodbtypes.AttributeValueMemberS)
	if !ok || lockIDVal.Value != vpcID {
		t.Errorf("LockID = %v, want %s", item["LockID"], vpcID)
	}

	ownerVal, ok := item["Owner"].(*dynamodbtypes.AttributeValueMemberS)
	if !ok || ownerVal.Value != owner {
		t.Errorf("Owner = %v, want %s", item["Owner"], owner)
	}

	expiresVal, ok := item["ExpiresAt"].(*dynamodbtypes.AttributeValueMemberN)
	expectedExpires := strconv.FormatInt(now.Add(lease).Unix(), 10)
	if !ok || expiresVal.Value != expectedExpires {
		t.Errorf("ExpiresAt = %v, want %s", item["ExpiresAt"], expectedExpires)
	}

	// Check expression attribute values
	nowVal, ok := attrValues[":now"].(*dynamodbtypes.AttributeValueMemberN)
	expectedNow := strconv.FormatInt(now.Unix(), 10)
	if !ok || nowVal.Value != expectedNow {
		t.Errorf(":now = %v, want %s", attrValues[":now"], expectedNow)
	}
}

func TestAcquireLock_Success(t *testing.T) {
	ctx := context.Background()
	log := logger.NewCustomLogger(&strings.Builder{}, &strings.Builder{}, logger.LevelDebug, false)
	mock := &mockDynamoClient{}
	locker := NewDynamoLocker(mock, "vpcdrain-locks", log)

	err := locker.AcquireLock(ctx, "vpc-test", "runner-1", 10*time.Minute)
	if err != nil {
		t.Fatalf("expected nil error on AcquireLock, got %v", err)
	}

	if mock.lastPutInput == nil {
		t.Fatal("expected PutItem to be called, got nil input")
	}
	if aws.ToString(mock.lastPutInput.TableName) != "vpcdrain-locks" {
		t.Errorf("expected table vpcdrain-locks, got %s", aws.ToString(mock.lastPutInput.TableName))
	}
}

func TestAcquireLock_ConditionalCheckFailed(t *testing.T) {
	ctx := context.Background()
	log := logger.NewCustomLogger(&strings.Builder{}, &strings.Builder{}, logger.LevelDebug, false)

	mock := &mockDynamoClient{
		putItemFn: func(ctx context.Context, params *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			return nil, &smithy.GenericAPIError{
				Code:    "ConditionalCheckFailedException",
				Message: "The conditional request failed",
			}
		},
	}

	locker := NewDynamoLocker(mock, "vpcdrain-locks", log)

	err := locker.AcquireLock(ctx, "vpc-test", "runner-1", 10*time.Minute)
	if err == nil {
		t.Fatal("expected lock conflict error, got nil")
	}

	if !strings.Contains(err.Error(), "distributed lock conflict") || !strings.Contains(err.Error(), "already locked") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReleaseLock(t *testing.T) {
	ctx := context.Background()
	log := logger.NewCustomLogger(&strings.Builder{}, &strings.Builder{}, logger.LevelDebug, false)
	mock := &mockDynamoClient{}
	locker := NewDynamoLocker(mock, "vpcdrain-locks", log)

	err := locker.ReleaseLock(ctx, "vpc-test")
	if err != nil {
		t.Fatalf("expected nil error on ReleaseLock, got %v", err)
	}

	if mock.lastDeleteInput == nil {
		t.Fatal("expected DeleteItem to be called, got nil input")
	}
	if aws.ToString(mock.lastDeleteInput.TableName) != "vpcdrain-locks" {
		t.Errorf("expected table vpcdrain-locks, got %s", aws.ToString(mock.lastDeleteInput.TableName))
	}
	keyVal := mock.lastDeleteInput.Key["LockID"].(*dynamodbtypes.AttributeValueMemberS).Value
	if keyVal != "vpc-test" {
		t.Errorf("deleted key = %s, want vpc-test", keyVal)
	}
}
