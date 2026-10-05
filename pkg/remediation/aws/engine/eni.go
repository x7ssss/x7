package engine

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
)

// PollOptions configures the retry and backoff behavior for ENI polling.
type PollOptions struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Timeout         time.Duration
	Multiplier      float64
	JitterFraction  float64
	Logger          logger.Logger
	RandFunc        func() float64
}

// DefaultPollOptions returns standard production-grade polling options.
func DefaultPollOptions(l logger.Logger) PollOptions {
	return PollOptions{
		InitialInterval: 2 * time.Second,
		MaxInterval:     15 * time.Second,
		Timeout:         5 * time.Minute,
		Multiplier:      1.5,
		JitterFraction:  0.2,
		Logger:          l,
		RandFunc:        rand.Float64,
	}
}

// FastPollOptions returns accelerated polling options for unit tests.
func FastPollOptions(l logger.Logger) PollOptions {
	return PollOptions{
		InitialInterval: 5 * time.Millisecond,
		MaxInterval:     20 * time.Millisecond,
		Timeout:         500 * time.Millisecond,
		Multiplier:      1.5,
		JitterFraction:  0.0,
		Logger:          l,
		RandFunc:        func() float64 { return 0.5 },
	}
}

// IdentifyParentService examines the ENI metadata to determine the managing AWS service.
func IdentifyParentService(eni ec2types.NetworkInterface) string {
	desc := aws.ToString(eni.Description)
	ifaceType := string(eni.InterfaceType)

	var ownerID string
	if eni.Attachment != nil {
		ownerID = aws.ToString(eni.Attachment.InstanceOwnerId)
	}

	// 1. AWS Lambda Hyperplane ENIs
	if strings.Contains(desc, "AWS Lambda VPC ENI") ||
		strings.Contains(desc, "AWS_Lambda_") ||
		ifaceType == "lambda" ||
		(ownerID == "amazon-aws" && strings.Contains(desc, "Lambda")) {
		return "AWS Lambda (Hyperplane ENI)"
	}

	// 2. Amazon ECS (Fargate)
	if strings.Contains(desc, "arn:aws:ecs:") ||
		ownerID == "amazon-ecs" ||
		(ownerID == "amazon-aws" && strings.Contains(desc, "ecs")) {
		return "Amazon ECS (Fargate Task ENI)"
	}

	// 3. Elastic Load Balancing (ALB / NLB / Gateway LB)
	if strings.HasPrefix(desc, "ELB ") ||
		strings.Contains(desc, "ELB app/") ||
		strings.Contains(desc, "ELB net/") ||
		strings.Contains(desc, "ELB gwy/") ||
		ownerID == "amazon-elb" {
		return "Elastic Load Balancing (ALB/NLB)"
	}

	// 4. NAT Gateway
	if ifaceType == string(ec2types.NetworkInterfaceTypeNatGateway) ||
		strings.Contains(desc, "Interface for NAT Gateway") {
		return "NAT Gateway"
	}

	// 5. VPC Interface Endpoint (PrivateLink)
	if ifaceType == string(ec2types.NetworkInterfaceTypeVpcEndpoint) ||
		strings.Contains(desc, "VPC Endpoint Interface") {
		return "VPC Interface Endpoint (PrivateLink)"
	}

	// 6. Transit Gateway
	if ifaceType == string(ec2types.NetworkInterfaceTypeTransitGateway) ||
		strings.Contains(desc, "Transit Gateway") {
		return "Transit Gateway VPC Attachment"
	}

	// 7. Amazon EFS
	if strings.Contains(desc, "Amazon EFS") {
		return "Amazon EFS Mount Target"
	}

	// 8. Managed database services (RDS, ElastiCache, Redshift)
	if strings.Contains(desc, "RDSNetworkInterface") {
		return "Amazon RDS"
	}
	if strings.Contains(desc, "ElastiCache") {
		return "Amazon ElastiCache"
	}
	if strings.Contains(desc, "Redshift") {
		return "Amazon Redshift"
	}

	// 9. Generic AWS-managed or attached ENIs
	if ownerID == "amazon-aws" && desc != "" {
		return fmt.Sprintf("AWS Managed (%s)", desc)
	}

	if desc != "" {
		return desc
	}

	return "Standard / Unmanaged ENI"
}

// CalculateNextBackoff applies exponential backoff with jitter.
func CalculateNextBackoff(current time.Duration, max time.Duration, multiplier float64, jitterFraction float64, randFn func() float64) time.Duration {
	next := time.Duration(float64(current) * multiplier)
	if next > max {
		next = max
	}

	if jitterFraction > 0 && randFn != nil {
		// jitter is uniformly distributed between [-jitterFraction, +jitterFraction]
		jitterRange := (randFn()*2.0 - 1.0) * jitterFraction
		jitterOffset := time.Duration(float64(next) * jitterRange)
		next = next + jitterOffset
	}

	if next < 0 {
		return current
	}
	return next
}

// PollForENICleanup polls DescribeNetworkInterfaces with exponential backoff and jitter
// until 0 active interfaces remain for the VPC, or returns a timeout error.
func PollForENICleanup(ctx context.Context, client awsclient.EC2Client, vpcID string, opts PollOptions) error {
	deadline := time.Now().Add(opts.Timeout)
	interval := opts.InitialInterval

	if opts.RandFunc == nil {
		opts.RandFunc = rand.Float64
	}

	pollAttempt := 0

	for {
		pollAttempt++

		// Query remaining network interfaces for the target VPC
		output, err := client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
			Filters: []ec2types.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{vpcID},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to describe network interfaces for VPC %s: %w", vpcID, err)
		}

		if len(output.NetworkInterfaces) == 0 {
			if opts.Logger != nil && pollAttempt > 1 {
				opts.Logger.Success("All requester-managed and active ENIs for VPC %s have cleanly drained", vpcID)
			}
			return nil
		}

		// Inspect remaining interfaces
		type LingeringENI struct {
			ID      string
			Service string
			Status  string
		}
		var lingering []LingeringENI
		for _, eni := range output.NetworkInterfaces {
			eniID := aws.ToString(eni.NetworkInterfaceId)
			svc := IdentifyParentService(eni)
			status := string(eni.Status)
			lingering = append(lingering, LingeringENI{ID: eniID, Service: svc, Status: status})

			// If any standard unattached ENI is available, attempt deletion directly
			if eni.Status == ec2types.NetworkInterfaceStatusAvailable && eni.Attachment == nil {
				_, _ = client.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{
					NetworkInterfaceId: eni.NetworkInterfaceId,
				})
			}
		}

		if opts.Logger != nil {
			var details []string
			for _, l := range lingering {
				details = append(details, fmt.Sprintf("%s (%s: %s)", l.ID, l.Service, l.Status))
			}
			opts.Logger.Info("Waiting for %d ENI(s) to drain: %s [retrying in %v]",
				len(lingering), strings.Join(details, ", "), interval)
		}

		// Check deadline and context
		if time.Now().After(deadline) {
			var errDetails []string
			for _, l := range lingering {
				errDetails = append(errDetails, fmt.Sprintf("%s [%s, status=%s]", l.ID, l.Service, l.Status))
			}
			return fmt.Errorf("timed out after %v waiting for %d ENIs to drain in VPC %s: %s",
				opts.Timeout, len(lingering), vpcID, strings.Join(errDetails, "; "))
		}

		// Sleep with backoff
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}

		interval = CalculateNextBackoff(interval, opts.MaxInterval, opts.Multiplier, opts.JitterFraction, opts.RandFunc)
	}
}
