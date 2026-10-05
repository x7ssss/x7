package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
)

type mockEC2ENIClient struct {
	awsclient.EC2Client
	describeCalls int
	responses     []*ec2.DescribeNetworkInterfacesOutput
	repeatLast    bool
	deleteCalls   int
}

func (m *mockEC2ENIClient) DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	idx := m.describeCalls
	m.describeCalls++
	if len(m.responses) > 0 {
		if idx < len(m.responses) {
			return m.responses[idx], nil
		}
		if m.repeatLast {
			return m.responses[len(m.responses)-1], nil
		}
	}
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}

func (m *mockEC2ENIClient) DeleteNetworkInterface(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
	m.deleteCalls++
	return &ec2.DeleteNetworkInterfaceOutput{}, nil
}

func TestIdentifyParentService(t *testing.T) {
	tests := []struct {
		name     string
		eni      ec2types.NetworkInterface
		expected string
	}{
		{
			name: "Lambda Hyperplane ENI via description",
			eni: ec2types.NetworkInterface{
				Description: aws.String("AWS Lambda VPC ENI-49cf0b3d-4c3e"),
				Attachment: &ec2types.NetworkInterfaceAttachment{
					InstanceOwnerId: aws.String("amazon-aws"),
				},
			},
			expected: "AWS Lambda (Hyperplane ENI)",
		},
		{
			name: "ECS Fargate ENI via ARN description",
			eni: ec2types.NetworkInterface{
				Description: aws.String("arn:aws:ecs:us-west-2:123456789012:attachment/a1b2c3d4"),
				Attachment: &ec2types.NetworkInterfaceAttachment{
					InstanceOwnerId: aws.String("amazon-aws"),
				},
			},
			expected: "Amazon ECS (Fargate Task ENI)",
		},
		{
			name: "Application Load Balancer",
			eni: ec2types.NetworkInterface{
				Description: aws.String("ELB app/my-alb/1234567890abcdef"),
				Attachment: &ec2types.NetworkInterfaceAttachment{
					InstanceOwnerId: aws.String("amazon-elb"),
				},
			},
			expected: "Elastic Load Balancing (ALB/NLB)",
		},
		{
			name: "NAT Gateway",
			eni: ec2types.NetworkInterface{
				InterfaceType: ec2types.NetworkInterfaceTypeNatGateway,
				Description:   aws.String("Interface for NAT Gateway nat-0123456789abcdef0"),
			},
			expected: "NAT Gateway",
		},
		{
			name: "VPC Interface Endpoint",
			eni: ec2types.NetworkInterface{
				InterfaceType: ec2types.NetworkInterfaceTypeVpcEndpoint,
				Description:   aws.String("VPC Endpoint Interface vpce-0123456789abcdef0"),
			},
			expected: "VPC Interface Endpoint (PrivateLink)",
		},
		{
			name: "Transit Gateway Attachment",
			eni: ec2types.NetworkInterface{
				InterfaceType: ec2types.NetworkInterfaceTypeTransitGateway,
				Description:   aws.String("Transit Gateway attachment tgw-attach-123"),
			},
			expected: "Transit Gateway VPC Attachment",
		},
		{
			name: "Amazon EFS Mount Target",
			eni: ec2types.NetworkInterface{
				Description: aws.String("Amazon EFS mount target for fs-123"),
			},
			expected: "Amazon EFS Mount Target",
		},
		{
			name: "Amazon RDS Instance",
			eni: ec2types.NetworkInterface{
				Description: aws.String("RDSNetworkInterface"),
			},
			expected: "Amazon RDS",
		},
		{
			name: "Unmanaged ENI with description",
			eni: ec2types.NetworkInterface{
				Description: aws.String("Custom-Tooling-ENI"),
			},
			expected: "Custom-Tooling-ENI",
		},
		{
			name:     "Blank unmanaged ENI",
			eni:      ec2types.NetworkInterface{},
			expected: "Standard / Unmanaged ENI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IdentifyParentService(tt.eni)
			if got != tt.expected {
				t.Errorf("IdentifyParentService() = %q; want %q", got, tt.expected)
			}
		})
	}
}

func TestCalculateNextBackoff(t *testing.T) {
	current := 100 * time.Millisecond
	max := 500 * time.Millisecond
	multiplier := 2.0

	// Without jitter
	next := CalculateNextBackoff(current, max, multiplier, 0.0, nil)
	if next != 200*time.Millisecond {
		t.Errorf("expected 200ms, got %v", next)
	}

	// Exceeding max
	nextMax := CalculateNextBackoff(300*time.Millisecond, max, multiplier, 0.0, nil)
	if nextMax != max {
		t.Errorf("expected %v (max), got %v", max, nextMax)
	}

	// With predictable jitter (+10%)
	fixedRand := func() float64 { return 1.0 } // (1.0 * 2 - 1) = +1.0 * 0.1 = +10%
	nextJitter := CalculateNextBackoff(current, max, multiplier, 0.1, fixedRand)
	expectedWithJitter := 220 * time.Millisecond
	if nextJitter != expectedWithJitter {
		t.Errorf("expected %v with jitter, got %v", expectedWithJitter, nextJitter)
	}
}

func TestPollForENICleanup(t *testing.T) {
	ctx := context.Background()
	log := logger.NewCustomLogger(&strings.Builder{}, &strings.Builder{}, logger.LevelDebug, false)

	t.Run("immediate return when no ENIs exist", func(t *testing.T) {
		mock := &mockEC2ENIClient{
			responses: []*ec2.DescribeNetworkInterfacesOutput{
				{NetworkInterfaces: []ec2types.NetworkInterface{}},
			},
		}

		opts := FastPollOptions(log)
		err := PollForENICleanup(ctx, mock, "vpc-12345", opts)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if mock.describeCalls != 1 {
			t.Errorf("expected 1 call, got %d", mock.describeCalls)
		}
	})

	t.Run("polls and succeeds once ENIs drain", func(t *testing.T) {
		mock := &mockEC2ENIClient{
			responses: []*ec2.DescribeNetworkInterfacesOutput{
				{
					NetworkInterfaces: []ec2types.NetworkInterface{
						{
							NetworkInterfaceId: aws.String("eni-001"),
							Description:        aws.String("AWS Lambda VPC ENI-1"),
							Status:             ec2types.NetworkInterfaceStatusInUse,
						},
					},
				},
				{
					NetworkInterfaces: []ec2types.NetworkInterface{
						{
							NetworkInterfaceId: aws.String("eni-001"),
							Description:        aws.String("AWS Lambda VPC ENI-1"),
							Status:             ec2types.NetworkInterfaceStatusInUse,
						},
					},
				},
				{
					NetworkInterfaces: []ec2types.NetworkInterface{}, // drained!
				},
			},
		}

		opts := FastPollOptions(log)
		err := PollForENICleanup(ctx, mock, "vpc-12345", opts)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if mock.describeCalls != 3 {
			t.Errorf("expected 3 describe calls, got %d", mock.describeCalls)
		}
	})

	t.Run("times out when ENIs refuse to drain", func(t *testing.T) {
		mock := &mockEC2ENIClient{
			repeatLast: true,
			responses: []*ec2.DescribeNetworkInterfacesOutput{
				{
					NetworkInterfaces: []ec2types.NetworkInterface{
						{
							NetworkInterfaceId: aws.String("eni-stuck"),
							Description:        aws.String("ELB app/lingering-alb"),
							Status:             ec2types.NetworkInterfaceStatusInUse,
						},
					},
				},
			},
		}

		opts := FastPollOptions(log)
		opts.Timeout = 40 * time.Millisecond // very short timeout
		opts.InitialInterval = 10 * time.Millisecond

		err := PollForENICleanup(ctx, mock, "vpc-12345", opts)
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if !strings.Contains(err.Error(), "timed out after") || !strings.Contains(err.Error(), "eni-stuck") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("aborts on context cancellation", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(context.Background())
		mock := &mockEC2ENIClient{
			responses: []*ec2.DescribeNetworkInterfacesOutput{
				{
					NetworkInterfaces: []ec2types.NetworkInterface{
						{
							NetworkInterfaceId: aws.String("eni-never-leaves"),
							Description:        aws.String("arn:aws:ecs:task"),
							Status:             ec2types.NetworkInterfaceStatusInUse,
						},
					},
				},
			},
		}

		opts := FastPollOptions(log)
		opts.Timeout = 10 * time.Second
		opts.InitialInterval = 50 * time.Millisecond

		go func() {
			time.Sleep(15 * time.Millisecond)
			cancel()
		}()

		err := PollForENICleanup(cancelCtx, mock, "vpc-12345", opts)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled error, got: %v", err)
		}
	})
}
