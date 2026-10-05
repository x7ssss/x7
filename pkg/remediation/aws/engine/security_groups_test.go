package engine

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
)

type mockTwoPassEC2Client struct {
	awsclient.EC2Client
	mu             sync.Mutex
	revokedIngress map[string]int
	revokedEgress  map[string]int
	deleteAttempts map[string]int
	deletedSGs     []string
}

func newMockTwoPassEC2Client() *mockTwoPassEC2Client {
	return &mockTwoPassEC2Client{
		revokedIngress: make(map[string]int),
		revokedEgress:  make(map[string]int),
		deleteAttempts: make(map[string]int),
	}
}

func (m *mockTwoPassEC2Client) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{
		SecurityGroups: []ec2types.SecurityGroup{
			{
				GroupId:   aws.String("sg-default"),
				GroupName: aws.String("default"),
				IpPermissions: []ec2types.IpPermission{
					{IpProtocol: aws.String("-1")},
				},
				IpPermissionsEgress: []ec2types.IpPermission{
					{IpProtocol: aws.String("-1")},
				},
			},
			{
				GroupId:   aws.String("sg-frontend"),
				GroupName: aws.String("frontend-sg"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol:       aws.String("tcp"),
						FromPort:         aws.Int32(443),
						ToPort:           aws.Int32(443),
						UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-backend")}},
					},
				},
				IpPermissionsEgress: []ec2types.IpPermission{
					{
						IpProtocol:       aws.String("tcp"),
						FromPort:         aws.Int32(8080),
						ToPort:           aws.Int32(8080),
						UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-backend")}},
					},
				},
			},
			{
				GroupId:   aws.String("sg-backend"),
				GroupName: aws.String("backend-sg"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol:       aws.String("tcp"),
						FromPort:         aws.Int32(8080),
						ToPort:           aws.Int32(8080),
						UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-frontend")}},
					},
				},
				IpPermissionsEgress: []ec2types.IpPermission{
					{
						IpProtocol:       aws.String("tcp"),
						FromPort:         aws.Int32(443),
						ToPort:           aws.Int32(443),
						UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-frontend")}},
					},
				},
			},
		},
	}, nil
}

func (m *mockTwoPassEC2Client) RevokeSecurityGroupIngress(ctx context.Context, params *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sgID := aws.ToString(params.GroupId)
	m.revokedIngress[sgID] += len(params.IpPermissions)
	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}

func (m *mockTwoPassEC2Client) RevokeSecurityGroupEgress(ctx context.Context, params *ec2.RevokeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sgID := aws.ToString(params.GroupId)
	m.revokedEgress[sgID] += len(params.IpPermissions)
	return &ec2.RevokeSecurityGroupEgressOutput{}, nil
}

func (m *mockTwoPassEC2Client) DeleteSecurityGroup(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sgID := aws.ToString(params.GroupId)
	m.deleteAttempts[sgID]++

	// Simulate transient DependencyViolation on first attempt for sg-backend
	if sgID == "sg-backend" && m.deleteAttempts[sgID] == 1 {
		return nil, &smithy.GenericAPIError{
			Code:    "DependencyViolation",
			Message: "resource sg-backend has a dependent object",
		}
	}

	m.deletedSGs = append(m.deletedSGs, sgID)
	return &ec2.DeleteSecurityGroupOutput{}, nil
}

func TestTwoPassSecurityGroupStripper(t *testing.T) {
	ctx := context.Background()
	log := logger.NewCustomLogger(&strings.Builder{}, &strings.Builder{}, logger.LevelDebug, false)
	client := newMockTwoPassEC2Client()

	stripper := NewTwoPassSecurityGroupStripper(
		client,
		log,
		2*time.Second,
		5*time.Millisecond,
		20*time.Millisecond,
	)

	// Execute Two-Pass stripping & eradication
	err := stripper.StripAndEradicate(ctx, "vpc-test-circular")
	if err != nil {
		t.Fatalf("StripAndEradicate failed: %v", err)
	}

	// 1. Pass 1 Neutralize Assertions
	if client.revokedIngress["sg-frontend"] != 1 {
		t.Errorf("expected 1 ingress rule revoked on sg-frontend, got %d", client.revokedIngress["sg-frontend"])
	}
	if client.revokedEgress["sg-frontend"] != 1 {
		t.Errorf("expected 1 egress rule revoked on sg-frontend, got %d", client.revokedEgress["sg-frontend"])
	}
	if client.revokedIngress["sg-backend"] != 1 {
		t.Errorf("expected 1 ingress rule revoked on sg-backend, got %d", client.revokedIngress["sg-backend"])
	}
	if client.revokedEgress["sg-backend"] != 1 {
		t.Errorf("expected 1 egress rule revoked on sg-backend, got %d", client.revokedEgress["sg-backend"])
	}

	// 2. Pass 2 Eradicate Assertions
	// Verify custom SGs were deleted
	if len(client.deletedSGs) != 2 {
		t.Fatalf("expected 2 custom SGs deleted, got %d: %v", len(client.deletedSGs), client.deletedSGs)
	}

	// Verify default SG was NEVER deleted
	for _, sgID := range client.deletedSGs {
		if sgID == "sg-default" {
			t.Error("default security group was deleted; it must be skipped")
		}
	}

	// Verify DependencyViolation retry was handled for sg-backend
	if client.deleteAttempts["sg-backend"] < 2 {
		t.Errorf("expected at least 2 delete attempts for sg-backend due to DependencyViolation, got %d",
			client.deleteAttempts["sg-backend"])
	}
}
