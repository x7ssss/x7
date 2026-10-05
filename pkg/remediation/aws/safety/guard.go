package safety

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
)

// DeniedEnvironments defines environment names that must never be deleted.
var DeniedEnvironments = []string{
	"production",
	"prod",
	"staging",
	"shared",
	"core",
}

// ProtectedTagKeys defines tags whose mere presence protects a VPC from deletion.
var ProtectedTagKeys = []string{
	"donotdelete",
}

// ScopeTag represents a key-value tag pair required for targeting a VPC.
type ScopeTag struct {
	Key   string
	Value string
}

// ParseScopeTag parses a "Key=Value" tag string.
func ParseScopeTag(tagStr string) (*ScopeTag, error) {
	tagStr = strings.TrimSpace(tagStr)
	if tagStr == "" {
		return nil, fmt.Errorf("scope tag cannot be empty (expected format: Key=Value)")
	}

	parts := strings.SplitN(tagStr, "=", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid scope tag format %q: expected Key=Value", tagStr)
	}

	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])
	if key == "" {
		return nil, fmt.Errorf("invalid scope tag %q: tag key cannot be empty", tagStr)
	}

	return &ScopeTag{Key: key, Value: val}, nil
}

// Guard verifies all safety requirements before any operation can proceed.
type Guard struct {
	stsClient awsclient.STSClient
	ec2Client awsclient.EC2Client
}

// NewGuard constructs a Guard with STS and EC2 clients.
func NewGuard(stsClient awsclient.STSClient, ec2Client awsclient.EC2Client) *Guard {
	return &Guard{
		stsClient: stsClient,
		ec2Client: ec2Client,
	}
}

// SafetyResult contains validated metadata from the guard checks.
type SafetyResult struct {
	CallerAccountID string
	CallerArn       string
	Vpc             *ec2types.Vpc
	VpcTags         map[string]string
}

// VerifyAll executes caller identity check, VPC tag denylist verification, and scope tag matching.
func (g *Guard) VerifyAll(ctx context.Context, vpcID string, expectedAccountID string, rawScopeTag string) (*SafetyResult, error) {
	if strings.TrimSpace(vpcID) == "" {
		return nil, fmt.Errorf("target VPC ID must not be empty")
	}

	scopeTag, err := ParseScopeTag(rawScopeTag)
	if err != nil {
		return nil, fmt.Errorf("scope tag error: %w", err)
	}

	// 1. Caller Verification
	callerIdentity, err := g.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve STS caller identity: %w", err)
	}

	callerAccount := aws.ToString(callerIdentity.Account)
	callerArn := aws.ToString(callerIdentity.Arn)

	if expectedAccountID != "" && callerAccount != expectedAccountID {
		return nil, fmt.Errorf("cross-account blast radius protection: caller account ID %q does not match expected account ID %q", callerAccount, expectedAccountID)
	}

	// 2. Fetch VPC details
	vpcOutput, err := g.ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		VpcIds: []string{vpcID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPC %s: %w", vpcID, err)
	}

	if len(vpcOutput.Vpcs) == 0 {
		return nil, fmt.Errorf("VPC %s not found in account %s", vpcID, callerAccount)
	}

	vpc := &vpcOutput.Vpcs[0]
	tagMap := make(map[string]string)
	for _, t := range vpc.Tags {
		if t.Key != nil && t.Value != nil {
			tagMap[*t.Key] = *t.Value
		}
	}

	// 3. Hard Denylist Check
	if err := CheckDenylist(tagMap); err != nil {
		return nil, fmt.Errorf("safety denylist triggered for VPC %s: %w", vpcID, err)
	}

	// 4. Scope Tag Match Verification
	if err := CheckTagMatch(tagMap, scopeTag); err != nil {
		return nil, fmt.Errorf("scope tag mismatch for VPC %s: %w", vpcID, err)
	}

	return &SafetyResult{
		CallerAccountID: callerAccount,
		CallerArn:       callerArn,
		Vpc:             vpc,
		VpcTags:         tagMap,
	}, nil
}

// CheckDenylist ensures the VPC does not have protected environment or DoNotDelete tags.
func CheckDenylist(tags map[string]string) error {
	for k, v := range tags {
		lowerKey := strings.ToLower(strings.TrimSpace(k))
		lowerVal := strings.ToLower(strings.TrimSpace(v))

		// Check for DoNotDelete tag
		for _, protectedKey := range ProtectedTagKeys {
			if lowerKey == protectedKey {
				return fmt.Errorf("hard denylist violation: protected tag %q is present (value: %q)", k, v)
			}
		}

		// Check for Environment tag
		if lowerKey == "environment" || lowerKey == "env" {
			for _, env := range DeniedEnvironments {
				if lowerVal == env {
					return fmt.Errorf("hard denylist violation: Environment tag %q=%q is a protected environment", k, v)
				}
			}
		}
	}
	return nil
}

// CheckTagMatch checks whether the expected scope tag is present with the exact key and value.
func CheckTagMatch(tags map[string]string, expected *ScopeTag) error {
	val, ok := tags[expected.Key]
	if !ok {
		return fmt.Errorf("expected tag %q not found on VPC (present tags: %v)", expected.Key, mapKeys(tags))
	}
	if val != expected.Value {
		return fmt.Errorf("expected tag %s=%q, but found value %q on VPC", expected.Key, expected.Value, val)
	}
	return nil
}

// CheckSharedTransitGatewaySafety asserts that shared Transit Gateways are never deleted.
func CheckSharedTransitGatewaySafety(action string) error {
	if strings.EqualFold(action, "DeleteTransitGateway") {
		return fmt.Errorf("transit gateway guard: calling DeleteTransitGateway is strictly forbidden; only detach VPC attachments")
	}
	return nil
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
