package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
	"golang.org/x/sync/errgroup"
)

// TwoPassSecurityGroupStripper implements the two-pass algorithm to cleanly neutralize
// circular security group reference cycles and eradicate custom security groups.
type TwoPassSecurityGroupStripper struct {
	client    awsclient.EC2Client
	log       logger.Logger
	timeout   time.Duration
	baseDelay time.Duration
	maxDelay  time.Duration
}

// NewTwoPassSecurityGroupStripper creates a new TwoPassSecurityGroupStripper.
func NewTwoPassSecurityGroupStripper(
	client awsclient.EC2Client,
	log logger.Logger,
	timeout time.Duration,
	baseDelay time.Duration,
	maxDelay time.Duration,
) *TwoPassSecurityGroupStripper {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	if baseDelay <= 0 {
		baseDelay = 150 * time.Millisecond
	}
	if maxDelay <= 0 {
		maxDelay = 5 * time.Second
	}
	return &TwoPassSecurityGroupStripper{
		client:    client,
		log:       log,
		timeout:   timeout,
		baseDelay: baseDelay,
		maxDelay:  maxDelay,
	}
}

// Pass1Neutralize queries all security groups in the VPC, skips the default security group,
// and revokes all ingress and egress rules to sever dependency edges from the graph.
func (s *TwoPassSecurityGroupStripper) Pass1Neutralize(ctx context.Context, vpcID string) ([]ec2types.SecurityGroup, error) {
	s.log.Info("[Pass 1: Neutralize] Querying custom security groups and revoking ingress/egress rules...")

	output, err := s.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups for VPC %s: %w", vpcID, err)
	}

	var customSGs []ec2types.SecurityGroup
	var g errgroup.Group

	for _, sgItem := range output.SecurityGroups {
		sg := sgItem
		isDefault := aws.ToString(sg.GroupName) == "default"

		// Also revoke rules on default SG to break any inbound/outbound references to custom SGs
		if !isDefault {
			customSGs = append(customSGs, sg)
		}

		g.Go(func() error {
			sgID := aws.ToString(sg.GroupId)
			sgName := aws.ToString(sg.GroupName)

			// Revoke ingress rules
			if len(sg.IpPermissions) > 0 {
				s.log.Info("Pass 1: Revoking %d ingress rule(s) on SG %s (%s)", len(sg.IpPermissions), sgID, sgName)
				_, err := s.client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
					GroupId:       sg.GroupId,
					IpPermissions: sg.IpPermissions,
				})
				if err != nil && !isNotFoundError(err) {
					s.log.Warn("Pass 1: Failed to revoke ingress on %s: %v", sgID, err)
				}
			}

			// Revoke egress rules
			if len(sg.IpPermissionsEgress) > 0 {
				s.log.Info("Pass 1: Revoking %d egress rule(s) on SG %s (%s)", len(sg.IpPermissionsEgress), sgID, sgName)
				_, err := s.client.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{
					GroupId:       sg.GroupId,
					IpPermissions: sg.IpPermissionsEgress,
				})
				if err != nil && !isNotFoundError(err) {
					s.log.Warn("Pass 1: Failed to revoke egress on %s: %v", sgID, err)
				}
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("pass 1 rule revocation failed: %w", err)
	}

	s.log.Success("[Pass 1: Neutralize] Stripped all dependency edges from %d custom security groups", len(customSGs))
	return customSGs, nil
}

// Pass2Eradicate concurrently deletes all custom security groups using errgroup and
// resilient DependencyViolation backoff retries.
func (s *TwoPassSecurityGroupStripper) Pass2Eradicate(ctx context.Context, customSGs []ec2types.SecurityGroup) error {
	s.log.Info("[Pass 2: Eradicate] Concurrently deleting %d custom security groups via errgroup...", len(customSGs))

	var g errgroup.Group

	for _, sgItem := range customSGs {
		sg := sgItem
		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)

		g.Go(func() error {
			opName := fmt.Sprintf("DeleteSecurityGroup(%s: %s)", sgID, sgName)
			s.log.Info("Pass 2: Deleting custom SG %s (%s)...", sgID, sgName)

			return RetryOnDependencyViolation(
				ctx,
				opName,
				s.timeout,
				s.baseDelay,
				s.maxDelay,
				func() error {
					_, err := s.client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
						GroupId: sg.GroupId,
					})
					return err
				},
				s.log,
			)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("pass 2 security group eradication failed: %w", err)
	}

	s.log.Success("[Pass 2: Eradicate] Successfully deleted %d custom security groups", len(customSGs))
	return nil
}

// StripAndEradicate executes both Pass 1 (Neutralize) and Pass 2 (Eradicate) sequentially.
func (s *TwoPassSecurityGroupStripper) StripAndEradicate(ctx context.Context, vpcID string) error {
	customSGs, err := s.Pass1Neutralize(ctx, vpcID)
	if err != nil {
		return err
	}
	return s.Pass2Eradicate(ctx, customSGs)
}
