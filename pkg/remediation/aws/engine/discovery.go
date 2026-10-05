package engine

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
)

// DiscoverVPCResources queries AWS APIs to build a full inventory of all resources in the target VPC.
func DiscoverVPCResources(ctx context.Context, clients *awsclient.Clients, vpcID string, region string, accountID string, tags map[string]string) (*VPCInventory, error) {
	inv := &VPCInventory{
		VpcID:   vpcID,
		Region:  region,
		Account: accountID,
		Tags:    tags,
	}

	// 1. Discover Subnets first (useful for matching compute workloads)
	subnetsOutput, err := clients.EC2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe subnets: %w", err)
	}

	subnetMap := make(map[string]bool)
	for _, s := range subnetsOutput.Subnets {
		sID := aws.ToString(s.SubnetId)
		inv.Subnets = append(inv.Subnets, sID)
		subnetMap[sID] = true
	}

	// 2. Discover Tier 1: Compute (ECS & Lambda)
	if err := discoverECS(ctx, clients.ECS, subnetMap, inv); err != nil {
		// Non-fatal if ECS has no permissions/resources, but log or capture
	}
	if err := discoverLambda(ctx, clients.Lambda, vpcID, subnetMap, inv); err != nil {
		// Non-fatal if Lambda has no permissions/resources
	}

	// 3. Discover Tier 2: Ingress (ALB/NLB, Target Groups, VPC Endpoints)
	if err := discoverELBv2(ctx, clients.ELBv2, vpcID, inv); err != nil {
		return nil, fmt.Errorf("failed to discover load balancers: %w", err)
	}

	vpceOutput, err := clients.EC2.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPC endpoints: %w", err)
	}
	for _, ep := range vpceOutput.VpcEndpoints {
		inv.VpcEndpoints = append(inv.VpcEndpoints, aws.ToString(ep.VpcEndpointId))
	}

	// 4. Discover Tier 3: Egress (NAT Gateways, TGW Attachments, Peering Connections)
	natOutput, err := clients.EC2.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
		Filter: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe NAT gateways: %w", err)
	}

	eipMap := make(map[string]bool)
	for _, ng := range natOutput.NatGateways {
		if ng.State == ec2types.NatGatewayStateDeleted {
			continue
		}
		var allocIDs []string
		for _, addr := range ng.NatGatewayAddresses {
			aID := aws.ToString(addr.AllocationId)
			if aID != "" {
				allocIDs = append(allocIDs, aID)
				if !eipMap[aID] {
					eipMap[aID] = true
					inv.ElasticIPs = append(inv.ElasticIPs, aID)
				}
			}
		}
		inv.NatGateways = append(inv.NatGateways, NatGatewayRef{
			NatGatewayID:  aws.ToString(ng.NatGatewayId),
			State:         string(ng.State),
			AllocationIDs: allocIDs,
		})
	}

	tgwOutput, err := clients.EC2.DescribeTransitGatewayVpcAttachments(ctx, &ec2.DescribeTransitGatewayVpcAttachmentsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err == nil && tgwOutput != nil {
		for _, att := range tgwOutput.TransitGatewayVpcAttachments {
			if att.State != ec2types.TransitGatewayAttachmentStateDeleted {
				inv.TGWAttachments = append(inv.TGWAttachments, aws.ToString(att.TransitGatewayAttachmentId))
			}
		}
	}

	peeringOutput, err := clients.EC2.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("requester-vpc-info.vpc-id"), Values: []string{vpcID}},
		},
	})
	if err == nil && peeringOutput != nil {
		for _, pcx := range peeringOutput.VpcPeeringConnections {
			if pcx.Status != nil && pcx.Status.Code != ec2types.VpcPeeringConnectionStateReasonCodeDeleted {
				inv.PeeringConns = append(inv.PeeringConns, aws.ToString(pcx.VpcPeeringConnectionId))
			}
		}
	}

	// 5. Discover Tier 5 & 6: Security Groups & Route Tables
	sgOutput, err := clients.EC2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	for _, sg := range sgOutput.SecurityGroups {
		isDefault := aws.ToString(sg.GroupName) == "default"
		inv.SecurityGroups = append(inv.SecurityGroups, SecurityGroupRef{
			GroupID:           aws.ToString(sg.GroupId),
			GroupName:         aws.ToString(sg.GroupName),
			IngressRulesCount: len(sg.IpPermissions),
			EgressRulesCount:  len(sg.IpPermissionsEgress),
			IsDefault:         isDefault,
		})
	}

	rtOutput, err := clients.EC2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe route tables: %w", err)
	}

	for _, rt := range rtOutput.RouteTables {
		var isMain bool
		var assocs []RouteTableAssocRef
		for _, a := range rt.Associations {
			main := a.Main != nil && *a.Main
			if main {
				isMain = true
			}
			assocs = append(assocs, RouteTableAssocRef{
				AssociationID: aws.ToString(a.RouteTableAssociationId),
				SubnetID:      aws.ToString(a.SubnetId),
				Main:          main,
			})
		}
		inv.RouteTables = append(inv.RouteTables, RouteTableRef{
			RouteTableID: aws.ToString(rt.RouteTableId),
			IsMain:       isMain,
			Associations: assocs,
		})
	}

	// 6. Discover Tier 7: Internet Gateways
	igwOutput, err := clients.EC2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("attachment.vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe internet gateways: %w", err)
	}
	for _, igw := range igwOutput.InternetGateways {
		inv.InternetGateways = append(inv.InternetGateways, aws.ToString(igw.InternetGatewayId))
	}

	// 7. Discover active Network Interfaces
	eniOutput, err := clients.EC2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe network interfaces: %w", err)
	}
	for _, eni := range eniOutput.NetworkInterfaces {
		var owner string
		if eni.Attachment != nil {
			owner = aws.ToString(eni.Attachment.InstanceOwnerId)
		}
		inv.ActiveENIs = append(inv.ActiveENIs, ENIRef{
			NetworkInterfaceID: aws.ToString(eni.NetworkInterfaceId),
			InterfaceType:      string(eni.InterfaceType),
			Description:        aws.ToString(eni.Description),
			OwnerID:            owner,
			SubnetID:           aws.ToString(eni.SubnetId),
			ParentService:      IdentifyParentService(eni),
		})
	}

	return inv, nil
}

func discoverECS(ctx context.Context, ecsClient awsclient.ECSClient, subnetMap map[string]bool, inv *VPCInventory) error {
	if ecsClient == nil {
		return nil
	}
	clustersOutput, err := ecsClient.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return err
	}

	for _, clusterArn := range clustersOutput.ClusterArns {
		// Discover services
		servicesOutput, err := ecsClient.ListServices(ctx, &ecs.ListServicesInput{Cluster: aws.String(clusterArn)})
		if err == nil && len(servicesOutput.ServiceArns) > 0 {
			descOutput, err := ecsClient.DescribeServices(ctx, &ecs.DescribeServicesInput{
				Cluster:  aws.String(clusterArn),
				Services: servicesOutput.ServiceArns,
			})
			if err == nil {
				for _, svc := range descOutput.Services {
					if svc.NetworkConfiguration != nil && svc.NetworkConfiguration.AwsvpcConfiguration != nil {
						for _, sub := range svc.NetworkConfiguration.AwsvpcConfiguration.Subnets {
							if subnetMap[sub] {
								inv.ECSServices = append(inv.ECSServices, ECSServiceRef{
									ClusterArn:   clusterArn,
									ServiceArn:   aws.ToString(svc.ServiceArn),
									ServiceName:  aws.ToString(svc.ServiceName),
									DesiredCount: svc.DesiredCount,
								})
								break
							}
						}
					}
				}
			}
		}

		// Discover active tasks
		tasksOutput, err := ecsClient.ListTasks(ctx, &ecs.ListTasksInput{Cluster: aws.String(clusterArn)})
		if err == nil && len(tasksOutput.TaskArns) > 0 {
			descTasks, err := ecsClient.DescribeTasks(ctx, &ecs.DescribeTasksInput{
				Cluster: aws.String(clusterArn),
				Tasks:   tasksOutput.TaskArns,
			})
			if err == nil {
				for _, task := range descTasks.Tasks {
					for _, att := range task.Attachments {
						for _, detail := range att.Details {
							if aws.ToString(detail.Name) == "subnetId" && subnetMap[aws.ToString(detail.Value)] {
								inv.ECSTasks = append(inv.ECSTasks, ECSTaskRef{
									ClusterArn: clusterArn,
									TaskArn:    aws.ToString(task.TaskArn),
								})
								break
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func discoverLambda(ctx context.Context, lambdaClient awsclient.LambdaClient, vpcID string, subnetMap map[string]bool, inv *VPCInventory) error {
	if lambdaClient == nil {
		return nil
	}
	funcsOutput, err := lambdaClient.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return err
	}

	for _, fn := range funcsOutput.Functions {
		if fn.VpcConfig != nil {
			isTargetVpc := fn.VpcConfig.VpcId != nil && *fn.VpcConfig.VpcId == vpcID
			if !isTargetVpc {
				for _, s := range fn.VpcConfig.SubnetIds {
					if subnetMap[s] {
						isTargetVpc = true
						break
					}
				}
			}
			if isTargetVpc {
				inv.LambdaFuncs = append(inv.LambdaFuncs, LambdaFuncRef{
					FunctionName: aws.ToString(fn.FunctionName),
					FunctionArn:  aws.ToString(fn.FunctionArn),
				})
			}
		}
	}
	return nil
}

func discoverELBv2(ctx context.Context, elbClient awsclient.ELBv2Client, vpcID string, inv *VPCInventory) error {
	if elbClient == nil {
		return nil
	}
	lbsOutput, err := elbClient.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil {
		return err
	}

	for _, lb := range lbsOutput.LoadBalancers {
		if lb.VpcId != nil && *lb.VpcId == vpcID {
			inv.LoadBalancers = append(inv.LoadBalancers, LBRef{
				LoadBalancerArn:  aws.ToString(lb.LoadBalancerArn),
				LoadBalancerName: aws.ToString(lb.LoadBalancerName),
				Type:             string(lb.Type),
			})
		}
	}

	tgsOutput, err := elbClient.DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{})
	if err == nil && tgsOutput != nil {
		for _, tg := range tgsOutput.TargetGroups {
			if tg.VpcId != nil && *tg.VpcId == vpcID {
				inv.TargetGroups = append(inv.TargetGroups, TargetGroupRef{
					TargetGroupArn:  aws.ToString(tg.TargetGroupArn),
					TargetGroupName: aws.ToString(tg.TargetGroupName),
				})
			}
		}
	}

	return nil
}
