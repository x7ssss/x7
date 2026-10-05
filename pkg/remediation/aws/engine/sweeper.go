package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
	"golang.org/x/sync/errgroup"
)

// SweeperOptions configures the execution parameters for the teardown engine.
type SweeperOptions struct {
	ENIPollOpts   PollOptions
	Logger        logger.Logger
	VpcTimeout    time.Duration
	RetryInterval time.Duration
}

// DefaultSweeperOptions returns standard production options.
func DefaultSweeperOptions(log logger.Logger) SweeperOptions {
	return SweeperOptions{
		ENIPollOpts:   DefaultPollOptions(log),
		Logger:        log,
		VpcTimeout:    90 * time.Second,
		RetryInterval: 1 * time.Second,
	}
}

// FastSweeperOptions returns accelerated options for unit tests.
func FastSweeperOptions(log logger.Logger) SweeperOptions {
	return SweeperOptions{
		ENIPollOpts:   FastPollOptions(log),
		Logger:        log,
		VpcTimeout:    500 * time.Millisecond,
		RetryInterval: 10 * time.Millisecond,
	}
}

// Sweeper orchestrates the deterministic 8-tier teardown of a target VPC.
type Sweeper struct {
	clients *awsclient.Clients
	opts    SweeperOptions
}

// NewSweeper creates a new Sweeper engine.
func NewSweeper(clients *awsclient.Clients, opts SweeperOptions) *Sweeper {
	if opts.Logger == nil {
		opts.Logger = logger.NewLogger(logger.LevelInfo, false)
	}
	return &Sweeper{
		clients: clients,
		opts:    opts,
	}
}

// Execute runs all 8 topological teardown tiers in strict reverse-dependency order.
func (s *Sweeper) Execute(ctx context.Context, inv *VPCInventory) error {
	log := s.opts.Logger
	log.Info("Starting deterministic 8-tier teardown for VPC %s", inv.VpcID)

	// Tier 1: Compute (ECS Fargate & Lambda VPC Detachment)
	if err := s.ExecuteTier1Compute(ctx, inv); err != nil {
		return fmt.Errorf("tier 1 compute teardown failed: %w", err)
	}

	// Tier 2: Ingress (ALB/NLB, Target Groups, VPC Endpoints)
	if err := s.ExecuteTier2Ingress(ctx, inv); err != nil {
		return fmt.Errorf("tier 2 ingress teardown failed: %w", err)
	}

	// Tier 3: Egress (NAT Gateways, TGW Attachments, VPC Peering)
	if err := s.ExecuteTier3Egress(ctx, inv); err != nil {
		return fmt.Errorf("tier 3 egress teardown failed: %w", err)
	}

	// Tier 4: Elastic IPs (Poll NAT Gateways to deleted state, release EIPs)
	if err := s.ExecuteTier4ElasticIPs(ctx, inv); err != nil {
		return fmt.Errorf("tier 4 elastic IPs teardown failed: %w", err)
	}

	// Tier 5: Security Group Cycle Stripping (Revoke all ingress and egress rules)
	if err := s.ExecuteTier5SGCycleStripping(ctx, inv); err != nil {
		return fmt.Errorf("tier 5 security group cycle stripping failed: %w", err)
	}

	// Inter-tier barrier: Requester-Managed ENI Polling
	// Wait until all requester-managed ENIs (Lambda Hyperplane, ECS Fargate, ELB) have fully drained.
	log.Info("Polling requester-managed ENIs to drain completely before deleting network primitives...")
	if err := PollForENICleanup(ctx, s.clients.EC2, inv.VpcID, s.opts.ENIPollOpts); err != nil {
		return fmt.Errorf("requester-managed ENI drain failed: %w", err)
	}

	// Tier 6: SGs & Route Tables (Delete custom SGs in parallel, disassociate and delete custom route tables)
	if err := s.ExecuteTier6SGsAndRouteTables(ctx, inv); err != nil {
		return fmt.Errorf("tier 6 security groups & route tables teardown failed: %w", err)
	}

	// Tier 7: Gateways & Subnets (Detach/delete Internet Gateways, concurrently delete subnets)
	if err := s.ExecuteTier7GatewaysAndSubnets(ctx, inv); err != nil {
		return fmt.Errorf("tier 7 gateways and subnets teardown failed: %w", err)
	}

	// Tier 8: VPC Deletion (Call DeleteVpc with backoff retries)
	if err := s.ExecuteTier8VPC(ctx, inv); err != nil {
		return fmt.Errorf("tier 8 VPC deletion failed: %w", err)
	}

	log.Success("VPC %s and all associated ephemeral infrastructure successfully destroyed!", inv.VpcID)
	return nil
}

// ExecuteTier1Compute stops active ECS tasks, scales ECS services to 0, and detaches Lambda VPC configs.
func (s *Sweeper) ExecuteTier1Compute(ctx context.Context, inv *VPCInventory) error {
	log := s.opts.Logger
	log.Tier(1, "Compute", "Terminating active ECS Fargate tasks and scaling services to 0...")

	if s.clients.ECS != nil {
		// 1. Scale down ECS services
		for _, svc := range inv.ECSServices {
			log.Info("Scaling ECS service %s on cluster %s to desiredCount=0", svc.ServiceName, svc.ClusterArn)
			_, err := s.clients.ECS.UpdateService(ctx, &ecs.UpdateServiceInput{
				Cluster:      aws.String(svc.ClusterArn),
				Service:      aws.String(svc.ServiceArn),
				DesiredCount: aws.Int32(0),
			})
			if err != nil {
				log.Warn("Failed to scale ECS service %s: %v", svc.ServiceName, err)
			}
		}

		// 2. Stop running ECS tasks
		for _, task := range inv.ECSTasks {
			log.Info("Stopping ECS task %s on cluster %s", task.TaskArn, task.ClusterArn)
			_, err := s.clients.ECS.StopTask(ctx, &ecs.StopTaskInput{
				Cluster: aws.String(task.ClusterArn),
				Task:    aws.String(task.TaskArn),
				Reason:  aws.String("vpcdrain tier 1 compute teardown"),
			})
			if err != nil {
				log.Warn("Failed to stop ECS task %s: %v", task.TaskArn, err)
			}
		}
	}

	// 3. Detach Lambda VPC configurations to trigger Hyperplane ENI reclamation
	if s.clients.Lambda != nil {
		for _, fn := range inv.LambdaFuncs {
			log.Info("Detaching VPC configuration from Lambda function %s", fn.FunctionName)
			_, err := s.clients.Lambda.UpdateFunctionConfiguration(ctx, &lambda.UpdateFunctionConfigurationInput{
				FunctionName: aws.String(fn.FunctionName),
				VpcConfig: &lambdatypes.VpcConfig{
					SubnetIds:        []string{},
					SecurityGroupIds: []string{},
				},
			})
			if err != nil {
				log.Warn("Failed to clear VPC config on Lambda %s: %v", fn.FunctionName, err)
			}
		}
	}

	return nil
}

// ExecuteTier2Ingress deletes Load Balancers, Target Groups, and VPC interface endpoints.
func (s *Sweeper) ExecuteTier2Ingress(ctx context.Context, inv *VPCInventory) error {
	log := s.opts.Logger
	log.Tier(2, "Ingress", "Deleting Application/Network Load Balancers, Target Groups, and VPC Endpoints...")

	// 1. Delete Load Balancers
	if s.clients.ELBv2 != nil {
		for _, lb := range inv.LoadBalancers {
			log.Info("Deleting %s Load Balancer: %s", lb.Type, lb.LoadBalancerArn)
			_, err := s.clients.ELBv2.DeleteLoadBalancer(ctx, &elasticloadbalancingv2.DeleteLoadBalancerInput{
				LoadBalancerArn: aws.String(lb.LoadBalancerArn),
			})
			if err != nil {
				log.Warn("Failed to delete Load Balancer %s: %v", lb.LoadBalancerArn, err)
			}
		}

		// 2. Delete Target Groups
		for _, tg := range inv.TargetGroups {
			log.Info("Deleting ELB Target Group: %s", tg.TargetGroupArn)
			_, err := s.clients.ELBv2.DeleteTargetGroup(ctx, &elasticloadbalancingv2.DeleteTargetGroupInput{
				TargetGroupArn: aws.String(tg.TargetGroupArn),
			})
			if err != nil {
				log.Warn("Failed to delete Target Group %s: %v", tg.TargetGroupArn, err)
			}
		}
	}

	// 3. Delete VPC Endpoints
	if len(inv.VpcEndpoints) > 0 {
		log.Info("Deleting %d VPC endpoint(s): %v", len(inv.VpcEndpoints), inv.VpcEndpoints)
		_, err := s.clients.EC2.DeleteVpcEndpoints(ctx, &ec2.DeleteVpcEndpointsInput{
			VpcEndpointIds: inv.VpcEndpoints,
		})
		if err != nil {
			log.Warn("Failed to delete VPC endpoints: %v", err)
		}
	}

	return nil
}

// ExecuteTier3Egress deletes NAT Gateways, Transit Gateway VPC attachments, and peering connections.
func (s *Sweeper) ExecuteTier3Egress(ctx context.Context, inv *VPCInventory) error {
	log := s.opts.Logger
	log.Tier(3, "Egress", "Deleting NAT Gateways, Transit Gateway VPC attachments, and Peering Connections...")

	// 1. Delete NAT Gateways
	for _, ng := range inv.NatGateways {
		if ng.State != string(ec2types.NatGatewayStateDeleted) {
			log.Info("Deleting NAT Gateway: %s (State: %s)", ng.NatGatewayID, ng.State)
			_, err := s.clients.EC2.DeleteNatGateway(ctx, &ec2.DeleteNatGatewayInput{
				NatGatewayId: aws.String(ng.NatGatewayID),
			})
			if err != nil {
				log.Warn("Failed to delete NAT Gateway %s: %v", ng.NatGatewayID, err)
			}
		}
	}

	// 2. Delete Transit Gateway VPC Attachments
	// Guard: NEVER call DeleteTransitGateway! Only DeleteTransitGatewayVpcAttachment.
	for _, attID := range inv.TGWAttachments {
		log.Info("Detaching Transit Gateway attachment: %s", attID)
		_, err := s.clients.EC2.DeleteTransitGatewayVpcAttachment(ctx, &ec2.DeleteTransitGatewayVpcAttachmentInput{
			TransitGatewayAttachmentId: aws.String(attID),
		})
		if err != nil {
			log.Warn("Failed to delete Transit Gateway VPC attachment %s: %v", attID, err)
		}
	}

	// 3. Delete VPC Peering Connections
	for _, pcxID := range inv.PeeringConns {
		log.Info("Deleting VPC Peering Connection: %s", pcxID)
		_, err := s.clients.EC2.DeleteVpcPeeringConnection(ctx, &ec2.DeleteVpcPeeringConnectionInput{
			VpcPeeringConnectionId: aws.String(pcxID),
		})
		if err != nil {
			log.Warn("Failed to delete VPC Peering Connection %s: %v", pcxID, err)
		}
	}

	return nil
}

// ExecuteTier4ElasticIPs polls NAT Gateways to deleted state, then releases associated Elastic IPs.
func (s *Sweeper) ExecuteTier4ElasticIPs(ctx context.Context, inv *VPCInventory) error {
	log := s.opts.Logger
	log.Tier(4, "Elastic IPs", "Polling NAT Gateways to deleted status and releasing Elastic IPs...")

	// Poll NAT Gateways until they reach 'deleted' status
	if len(inv.NatGateways) > 0 {
		var activeNatIDs []string
		for _, ng := range inv.NatGateways {
			activeNatIDs = append(activeNatIDs, ng.NatGatewayID)
		}

		deadline := time.Now().Add(10 * time.Minute)
		interval := s.opts.RetryInterval
		if interval <= 0 {
			interval = 2 * time.Second
		}

		for len(activeNatIDs) > 0 {
			descOutput, err := s.clients.EC2.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
				NatGatewayIds: activeNatIDs,
			})
			if err != nil {
				log.Warn("Error describing NAT gateways during poll: %v", err)
			} else {
				var remaining []string
				for _, ng := range descOutput.NatGateways {
					if ng.State != ec2types.NatGatewayStateDeleted {
						remaining = append(remaining, aws.ToString(ng.NatGatewayId))
					}
				}
				activeNatIDs = remaining
			}

			if len(activeNatIDs) == 0 {
				log.Success("All NAT Gateways have reached 'deleted' status")
				break
			}

			if time.Now().After(deadline) {
				log.Warn("Timed out waiting for NAT Gateways %v to reach deleted status", activeNatIDs)
				break
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
	}

	// Release Elastic IPs
	for _, eip := range inv.ElasticIPs {
		log.Info("Releasing Elastic IP allocation: %s", eip)
		_, err := s.clients.EC2.ReleaseAddress(ctx, &ec2.ReleaseAddressInput{
			AllocationId: aws.String(eip),
		})
		if err != nil {
			log.Warn("Failed to release Elastic IP %s: %v", eip, err)
		}
	}

	return nil
}

// ExecuteTier5SGCycleStripping revokes all ingress and egress rules on all security groups
// in the VPC to eliminate circular dependency deadlocks.
func (s *Sweeper) ExecuteTier5SGCycleStripping(ctx context.Context, inv *VPCInventory) error {
	log := s.opts.Logger
	log.Tier(5, "Security Group Cycle Stripping", "Revoking all ingress & egress rules to break circular deadlocks...")

	// Fetch fresh security group permissions to ensure accuracy
	sgOutput, err := s.clients.EC2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{inv.VpcID}},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to describe security groups: %w", err)
	}

	var g errgroup.Group
	for _, sgItem := range sgOutput.SecurityGroups {
		sg := sgItem // capture loop variable
		g.Go(func() error {
			sgID := aws.ToString(sg.GroupId)
			sgName := aws.ToString(sg.GroupName)

			// 1. Revoke Ingress rules
			if len(sg.IpPermissions) > 0 {
				log.Info("Revoking %d ingress rule(s) from SG %s (%s)", len(sg.IpPermissions), sgID, sgName)
				_, err := s.clients.EC2.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
					GroupId:       sg.GroupId,
					IpPermissions: sg.IpPermissions,
				})
				if err != nil && !isNotFoundError(err) {
					log.Warn("Failed to revoke ingress rules on %s: %v", sgID, err)
				}
			}

			// 2. Revoke Egress rules
			if len(sg.IpPermissionsEgress) > 0 {
				log.Info("Revoking %d egress rule(s) from SG %s (%s)", len(sg.IpPermissionsEgress), sgID, sgName)
				_, err := s.clients.EC2.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{
					GroupId:       sg.GroupId,
					IpPermissions: sg.IpPermissionsEgress,
				})
				if err != nil && !isNotFoundError(err) {
					log.Warn("Failed to revoke egress rules on %s: %v", sgID, err)
				}
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	log.Success("All circular security group rules stripped successfully")
	return nil
}

// ExecuteTier6SGsAndRouteTables deletes custom security groups in parallel (skipping default SG),
// and disassociates and deletes custom route tables (skipping main route table).
func (s *Sweeper) ExecuteTier6SGsAndRouteTables(ctx context.Context, inv *VPCInventory) error {
	log := s.opts.Logger
	log.Tier(6, "SGs & Route Tables", "Deleting custom security groups and custom route tables...")

	// 1. Delete custom Security Groups concurrently via errgroup
	var g errgroup.Group
	for _, sg := range inv.SecurityGroups {
		if sg.IsDefault {
			log.Debug("Skipping default security group %s", sg.GroupID)
			continue
		}
		targetSG := sg
		g.Go(func() error {
			return s.deleteSGWithRetry(ctx, targetSG.GroupID, targetSG.GroupName)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("failed to delete security groups: %w", err)
	}

	// 2. Disassociate and delete custom Route Tables
	for _, rt := range inv.RouteTables {
		if rt.IsMain {
			log.Debug("Skipping main route table %s", rt.RouteTableID)
			continue
		}

		// Disassociate non-main associations
		for _, a := range rt.Associations {
			if !a.Main && a.AssociationID != "" {
				assocID := a.AssociationID
				log.Info("Disassociating Route Table %s from association %s", rt.RouteTableID, assocID)
				err := RetryOnDependencyViolation(ctx, fmt.Sprintf("DisassociateRouteTable(%s)", assocID), s.opts.VpcTimeout, s.opts.RetryInterval, 5*time.Second, func() error {
					_, err := s.clients.EC2.DisassociateRouteTable(ctx, &ec2.DisassociateRouteTableInput{
						AssociationId: aws.String(assocID),
					})
					return err
				}, log)
				if err != nil && !isNotFoundError(err) {
					log.Warn("Failed to disassociate route table %s: %v", rt.RouteTableID, err)
				}
			}
		}

		// Delete route table
		rtID := rt.RouteTableID
		log.Info("Deleting custom Route Table: %s", rtID)
		err := RetryOnDependencyViolation(ctx, fmt.Sprintf("DeleteRouteTable(%s)", rtID), s.opts.VpcTimeout, s.opts.RetryInterval, 5*time.Second, func() error {
			_, err := s.clients.EC2.DeleteRouteTable(ctx, &ec2.DeleteRouteTableInput{
				RouteTableId: aws.String(rtID),
			})
			return err
		}, log)
		if err != nil && !isNotFoundError(err) {
			log.Warn("Failed to delete Route Table %s: %v", rtID, err)
		}
	}

	return nil
}

// ExecuteTier7GatewaysAndSubnets detaches and deletes Internet Gateways, then deletes subnets concurrently.
func (s *Sweeper) ExecuteTier7GatewaysAndSubnets(ctx context.Context, inv *VPCInventory) error {
	log := s.opts.Logger
	log.Tier(7, "Gateways & Subnets", "Detaching/deleting Internet Gateways and concurrently deleting subnets...")

	// 1. Detach and delete Internet Gateways
	for _, igw := range inv.InternetGateways {
		igwID := igw
		log.Info("Detaching Internet Gateway %s from VPC %s", igwID, inv.VpcID)
		err := RetryOnDependencyViolation(ctx, fmt.Sprintf("DetachInternetGateway(%s)", igwID), s.opts.VpcTimeout, s.opts.RetryInterval, 5*time.Second, func() error {
			_, err := s.clients.EC2.DetachInternetGateway(ctx, &ec2.DetachInternetGatewayInput{
				InternetGatewayId: aws.String(igwID),
				VpcId:             aws.String(inv.VpcID),
			})
			return err
		}, log)
		if err != nil && !isNotFoundError(err) {
			log.Warn("Failed to detach IGW %s: %v", igwID, err)
		}

		log.Info("Deleting Internet Gateway %s", igwID)
		err = RetryOnDependencyViolation(ctx, fmt.Sprintf("DeleteInternetGateway(%s)", igwID), s.opts.VpcTimeout, s.opts.RetryInterval, 5*time.Second, func() error {
			_, err := s.clients.EC2.DeleteInternetGateway(ctx, &ec2.DeleteInternetGatewayInput{
				InternetGatewayId: aws.String(igwID),
			})
			return err
		}, log)
		if err != nil && !isNotFoundError(err) {
			log.Warn("Failed to delete IGW %s: %v", igwID, err)
		}
	}

	// 2. Delete subnets concurrently using errgroup
	var g errgroup.Group
	for _, sub := range inv.Subnets {
		subID := sub
		g.Go(func() error {
			return s.deleteSubnetWithRetry(ctx, subID)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("failed to delete subnets: %w", err)
	}

	return nil
}

// ExecuteTier8VPC deletes the VPC with exponential backoff retries until complete.
func (s *Sweeper) ExecuteTier8VPC(ctx context.Context, inv *VPCInventory) error {
	log := s.opts.Logger
	log.Tier(8, "VPC Deletion", "Calling ec2:DeleteVpc with backoff retries...")

	opName := fmt.Sprintf("DeleteVpc(%s)", inv.VpcID)
	err := RetryOnDependencyViolation(ctx, opName, s.opts.VpcTimeout, s.opts.RetryInterval, 10*time.Second, func() error {
		log.Info("Executing DeleteVpc for %s...", inv.VpcID)
		_, err := s.clients.EC2.DeleteVpc(ctx, &ec2.DeleteVpcInput{
			VpcId: aws.String(inv.VpcID),
		})
		return err
	}, log)

	if err != nil {
		return fmt.Errorf("failed to delete VPC %s: %w", inv.VpcID, err)
	}

	log.Success("VPC %s successfully deleted from AWS", inv.VpcID)
	return nil
}

func (s *Sweeper) deleteSGWithRetry(ctx context.Context, sgID string, sgName string) error {
	log := s.opts.Logger
	opName := fmt.Sprintf("DeleteSecurityGroup(%s: %s)", sgID, sgName)
	return RetryOnDependencyViolation(ctx, opName, 45*time.Second, s.opts.RetryInterval, 5*time.Second, func() error {
		log.Info("Deleting custom Security Group %s (%s)...", sgID, sgName)
		_, err := s.clients.EC2.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
			GroupId: aws.String(sgID),
		})
		return err
	}, log)
}

func (s *Sweeper) deleteSubnetWithRetry(ctx context.Context, subID string) error {
	log := s.opts.Logger
	opName := fmt.Sprintf("DeleteSubnet(%s)", subID)
	return RetryOnDependencyViolation(ctx, opName, 60*time.Second, s.opts.RetryInterval, 5*time.Second, func() error {
		log.Info("Deleting Subnet %s...", subID)
		_, err := s.clients.EC2.DeleteSubnet(ctx, &ec2.DeleteSubnetInput{
			SubnetId: aws.String(subID),
		})
		return err
	}, log)
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "NotFound") ||
		strings.Contains(msg, "DoesNotExist") ||
		strings.Contains(msg, "InvalidGroup.NotFound") ||
		strings.Contains(msg, "InvalidSubnetID.NotFound") ||
		strings.Contains(msg, "InvalidVpcID.NotFound")
}
