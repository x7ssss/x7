package safety

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
)

type mockSTSClient struct {
	awsclient.STSClient
	identityFn func(ctx context.Context, params *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.identityFn != nil {
		return m.identityFn(ctx, params)
	}
	return &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"),
		Arn:     aws.String("arn:aws:iam::123456789012:user/ci-deployer"),
	}, nil
}

type mockEC2Client struct {
	awsclient.EC2Client
	describeVpcsFn func(ctx context.Context, params *ec2.DescribeVpcsInput) (*ec2.DescribeVpcsOutput, error)
}

func (m *mockEC2Client) DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	if m.describeVpcsFn != nil {
		return m.describeVpcsFn(ctx, params)
	}
	return &ec2.DescribeVpcsOutput{
		Vpcs: []ec2types.Vpc{
			{
				VpcId: aws.String("vpc-0123456789abcdef0"),
				Tags: []ec2types.Tag{
					{Key: aws.String("Ephemeral"), Value: aws.String("true")},
					{Key: aws.String("Environment"), Value: aws.String("test")},
				},
			},
		},
	}, nil
}

func TestParseScopeTag(t *testing.T) {
	tests := []struct {
		input   string
		wantKey string
		wantVal string
		wantErr bool
	}{
		{"Ephemeral=true", "Ephemeral", "true", false},
		{"PR=123", "PR", "123", false},
		{"Key=Value=Extra", "Key", "Value=Extra", false},
		{"", "", "", true},
		{"NoEqualsSign", "", "", true},
		{" =val", "", "", true},
		{"  Key  =  Value  ", "Key", "Value", false},
	}

	for _, tt := range tests {
		tag, err := ParseScopeTag(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseScopeTag(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseScopeTag(%q) unexpected error: %v", tt.input, err)
			} else if tag.Key != tt.wantKey || tag.Value != tt.wantVal {
				t.Errorf("ParseScopeTag(%q) = (%s, %s); want (%s, %s)", tt.input, tag.Key, tag.Value, tt.wantKey, tt.wantVal)
			}
		}
	}
}

func TestGuardCallerVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("matching account succeeds", func(t *testing.T) {
		stsMock := &mockSTSClient{}
		ec2Mock := &mockEC2Client{}
		guard := NewGuard(stsMock, ec2Mock)

		res, err := guard.VerifyAll(ctx, "vpc-0123456789abcdef0", "123456789012", "Ephemeral=true")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.CallerAccountID != "123456789012" {
			t.Errorf("expected caller account 123456789012, got %s", res.CallerAccountID)
		}
	})

	t.Run("mismatched account fails", func(t *testing.T) {
		stsMock := &mockSTSClient{}
		ec2Mock := &mockEC2Client{}
		guard := NewGuard(stsMock, ec2Mock)

		_, err := guard.VerifyAll(ctx, "vpc-0123456789abcdef0", "999999999999", "Ephemeral=true")
		if err == nil {
			t.Fatal("expected account mismatch error, got nil")
		}
	})

	t.Run("empty expected account succeeds using caller account", func(t *testing.T) {
		stsMock := &mockSTSClient{}
		ec2Mock := &mockEC2Client{}
		guard := NewGuard(stsMock, ec2Mock)

		res, err := guard.VerifyAll(ctx, "vpc-0123456789abcdef0", "", "Ephemeral=true")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.CallerAccountID != "123456789012" {
			t.Errorf("expected caller account 123456789012, got %s", res.CallerAccountID)
		}
	})

	t.Run("sts failure returns error", func(t *testing.T) {
		stsMock := &mockSTSClient{
			identityFn: func(ctx context.Context, params *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
				return nil, errors.New("sts access denied")
			},
		}
		ec2Mock := &mockEC2Client{}
		guard := NewGuard(stsMock, ec2Mock)

		_, err := guard.VerifyAll(ctx, "vpc-0123456789abcdef0", "123456789012", "Ephemeral=true")
		if err == nil {
			t.Fatal("expected sts error, got nil")
		}
	})
}

func TestCheckDenylist(t *testing.T) {
	tests := []struct {
		name    string
		tags    map[string]string
		wantErr bool
	}{
		{
			name:    "safe ephemeral tags",
			tags:    map[string]string{"Ephemeral": "true", "Environment": "dev"},
			wantErr: false,
		},
		{
			name:    "production environment blocked",
			tags:    map[string]string{"Environment": "production"},
			wantErr: true,
		},
		{
			name:    "prod case-insensitive blocked",
			tags:    map[string]string{"ENVIRONMENT": "PROD"},
			wantErr: true,
		},
		{
			name:    "staging blocked",
			tags:    map[string]string{"Environment": "staging"},
			wantErr: true,
		},
		{
			name:    "shared blocked",
			tags:    map[string]string{"env": "shared"},
			wantErr: true,
		},
		{
			name:    "core blocked",
			tags:    map[string]string{"Env": "core"},
			wantErr: true,
		},
		{
			name:    "DoNotDelete tag present",
			tags:    map[string]string{"DoNotDelete": "true"},
			wantErr: true,
		},
		{
			name:    "donotdelete lower case present",
			tags:    map[string]string{"donotdelete": "any-reason"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckDenylist(tt.tags)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckDenylist() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckTagMatch(t *testing.T) {
	tags := map[string]string{
		"PR":        "456",
		"Ephemeral": "true",
	}

	t.Run("exact match succeeds", func(t *testing.T) {
		err := CheckTagMatch(tags, &ScopeTag{Key: "PR", Value: "456"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("value mismatch fails", func(t *testing.T) {
		err := CheckTagMatch(tags, &ScopeTag{Key: "PR", Value: "123"})
		if err == nil {
			t.Fatal("expected error on value mismatch, got nil")
		}
	})

	t.Run("missing key fails", func(t *testing.T) {
		err := CheckTagMatch(tags, &ScopeTag{Key: "NonExistent", Value: "val"})
		if err == nil {
			t.Fatal("expected error on missing key, got nil")
		}
	})
}

func TestCheckSharedTransitGatewaySafety(t *testing.T) {
	if err := CheckSharedTransitGatewaySafety("DeleteTransitGateway"); err == nil {
		t.Fatal("expected DeleteTransitGateway to be forbidden, got nil")
	}

	if err := CheckSharedTransitGatewaySafety("DeleteTransitGatewayVpcAttachment"); err != nil {
		t.Fatalf("unexpected error for DeleteTransitGatewayVpcAttachment: %v", err)
	}
}
