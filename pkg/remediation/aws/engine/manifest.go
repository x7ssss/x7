package engine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TierNames defines standard descriptive names for each of the 8 tiers.
var TierNames = map[int]string{
	1: "Compute (ECS Fargate & Lambda VPC Detachment)",
	2: "Ingress (ALB/NLB, Target Groups, VPC Endpoints)",
	3: "Egress (NAT Gateways, TGW Attachments, VPC Peering)",
	4: "Elastic IPs (Poll NAT Deletion & Release EIPs)",
	5: "Security Group Cycle Stripping (Revoke All Rules)",
	6: "SGs & Route Tables (Delete Custom SGs & Disassociate Route Tables)",
	7: "Gateways & Subnets (Detach/Delete IGWs & Concurrent Subnet Deletion)",
	8: "VPC Deletion (Delete VPC with Backoff Retries)",
}

// BuildManifest constructs a DryRunManifest from the discovered VPC inventory.
func BuildManifest(inv *VPCInventory) *DryRunManifest {
	target := TargetInfo{
		AccountID: inv.Account,
		Region:    inv.Region,
		VpcID:     inv.VpcID,
		Tags:      inv.Tags,
	}
	if target.Tags == nil {
		target.Tags = make(map[string]string)
	}

	tiers := make([]ExecutionTier, 8)
	for i := 1; i <= 8; i++ {
		tiers[i-1] = ExecutionTier{
			Tier:      i,
			Name:      TierNames[i],
			Resources: []PlanAction{},
		}
	}

	totalResourcesToDelete := 0
	totalRulesToStrip := 0

	// Tier 1: Compute
	for _, svc := range inv.ECSServices {
		tiers[0].Resources = append(tiers[0].Resources, PlanAction{
			ResourceID: svc.ServiceArn,
			Service:    "ecs",
			Action:     "ScaleDownService",
			Details:    fmt.Sprintf("Cluster: %s, Set desiredCount=0 (current: %d)", svc.ClusterArn, svc.DesiredCount),
		})
		totalResourcesToDelete++
	}
	for _, task := range inv.ECSTasks {
		tiers[0].Resources = append(tiers[0].Resources, PlanAction{
			ResourceID: task.TaskArn,
			Service:    "ecs",
			Action:     "StopTask",
			Details:    fmt.Sprintf("Cluster: %s, Stop active Fargate task", task.ClusterArn),
		})
		totalResourcesToDelete++
	}
	for _, fn := range inv.LambdaFuncs {
		tiers[0].Resources = append(tiers[0].Resources, PlanAction{
			ResourceID: fn.FunctionName,
			Service:    "lambda",
			Action:     "DisassociateVPCConfig",
			Details:    "Clear SubnetIds and SecurityGroupIds to trigger ENI release",
		})
		totalResourcesToDelete++
	}

	// Tier 2: Ingress
	for _, lb := range inv.LoadBalancers {
		tiers[1].Resources = append(tiers[1].Resources, PlanAction{
			ResourceID: lb.LoadBalancerArn,
			Service:    "elbv2",
			Action:     "DeleteLoadBalancer",
			Details:    fmt.Sprintf("Name: %s, Type: %s", lb.LoadBalancerName, lb.Type),
		})
		totalResourcesToDelete++
	}
	for _, tg := range inv.TargetGroups {
		tiers[1].Resources = append(tiers[1].Resources, PlanAction{
			ResourceID: tg.TargetGroupArn,
			Service:    "elbv2",
			Action:     "DeleteTargetGroup",
			Details:    fmt.Sprintf("Name: %s", tg.TargetGroupName),
		})
		totalResourcesToDelete++
	}
	for _, ep := range inv.VpcEndpoints {
		tiers[1].Resources = append(tiers[1].Resources, PlanAction{
			ResourceID: ep,
			Service:    "ec2",
			Action:     "DeleteVpcEndpoint",
			Details:    "Delete VPC endpoint interface/gateway",
		})
		totalResourcesToDelete++
	}

	// Tier 3: Egress
	for _, ng := range inv.NatGateways {
		tiers[2].Resources = append(tiers[2].Resources, PlanAction{
			ResourceID: ng.NatGatewayID,
			Service:    "ec2",
			Action:     "DeleteNatGateway",
			Details:    fmt.Sprintf("State: %s, Associated EIPs: %v", ng.State, ng.AllocationIDs),
		})
		totalResourcesToDelete++
	}
	for _, att := range inv.TGWAttachments {
		tiers[2].Resources = append(tiers[2].Resources, PlanAction{
			ResourceID: att,
			Service:    "ec2",
			Action:     "DeleteTransitGatewayVpcAttachment",
			Details:    "Detach VPC attachment from shared Transit Gateway",
		})
		totalResourcesToDelete++
	}
	for _, pcx := range inv.PeeringConns {
		tiers[2].Resources = append(tiers[2].Resources, PlanAction{
			ResourceID: pcx,
			Service:    "ec2",
			Action:     "DeleteVpcPeeringConnection",
			Details:    "Delete active VPC peering connection",
		})
		totalResourcesToDelete++
	}

	// Tier 4: Elastic IPs
	for _, ng := range inv.NatGateways {
		tiers[3].Resources = append(tiers[3].Resources, PlanAction{
			ResourceID: ng.NatGatewayID,
			Service:    "ec2",
			Action:     "PollNatGatewayDeleted",
			Details:    "Wait until NAT Gateway reaches deleted state",
		})
	}
	for _, eip := range inv.ElasticIPs {
		tiers[3].Resources = append(tiers[3].Resources, PlanAction{
			ResourceID: eip,
			Service:    "ec2",
			Action:     "ReleaseAddress",
			Details:    "Release Elastic IP allocation",
		})
		totalResourcesToDelete++
	}

	// Tier 5: Security Group Cycle Stripping
	for _, sg := range inv.SecurityGroups {
		if sg.IngressRulesCount > 0 {
			tiers[4].Resources = append(tiers[4].Resources, PlanAction{
				ResourceID: sg.GroupID,
				Service:    "ec2",
				Action:     "RevokeSecurityGroupIngress",
				Details:    fmt.Sprintf("Revoke %d ingress rule(s) (%s)", sg.IngressRulesCount, sg.GroupName),
			})
			totalRulesToStrip += sg.IngressRulesCount
		}
		if sg.EgressRulesCount > 0 {
			tiers[4].Resources = append(tiers[4].Resources, PlanAction{
				ResourceID: sg.GroupID,
				Service:    "ec2",
				Action:     "RevokeSecurityGroupEgress",
				Details:    fmt.Sprintf("Revoke %d egress rule(s) (%s)", sg.EgressRulesCount, sg.GroupName),
			})
			totalRulesToStrip += sg.EgressRulesCount
		}
	}

	// Tier 6: SGs & Route Tables
	for _, sg := range inv.SecurityGroups {
		if !sg.IsDefault {
			tiers[5].Resources = append(tiers[5].Resources, PlanAction{
				ResourceID: sg.GroupID,
				Service:    "ec2",
				Action:     "DeleteSecurityGroup",
				Details:    fmt.Sprintf("Custom Security Group: %s", sg.GroupName),
			})
			totalResourcesToDelete++
		}
	}
	for _, rt := range inv.RouteTables {
		if !rt.IsMain {
			for _, a := range rt.Associations {
				tiers[5].Resources = append(tiers[5].Resources, PlanAction{
					ResourceID: a.AssociationID,
					Service:    "ec2",
					Action:     "DisassociateRouteTable",
					Details:    fmt.Sprintf("Disassociate from Subnet: %s", a.SubnetID),
				})
			}
			tiers[5].Resources = append(tiers[5].Resources, PlanAction{
				ResourceID: rt.RouteTableID,
				Service:    "ec2",
				Action:     "DeleteRouteTable",
				Details:    "Delete custom route table",
			})
			totalResourcesToDelete++
		}
	}

	// Tier 7: Gateways & Subnets
	for _, igw := range inv.InternetGateways {
		tiers[6].Resources = append(tiers[6].Resources, PlanAction{
			ResourceID: igw,
			Service:    "ec2",
			Action:     "DetachAndDeleteInternetGateway",
			Details:    fmt.Sprintf("Detach from VPC %s then delete", inv.VpcID),
		})
		totalResourcesToDelete++
	}
	for _, sub := range inv.Subnets {
		tiers[6].Resources = append(tiers[6].Resources, PlanAction{
			ResourceID: sub,
			Service:    "ec2",
			Action:     "DeleteSubnet",
			Details:    "Concurrently delete subnet via errgroup",
		})
		totalResourcesToDelete++
	}

	// Tier 8: VPC Deletion
	tiers[7].Resources = append(tiers[7].Resources, PlanAction{
		ResourceID: inv.VpcID,
		Service:    "ec2",
		Action:     "DeleteVpc",
		Details:    "Deterministic VPC deletion with backoff retries",
	})
	totalResourcesToDelete++

	// Estimate duration
	duration := 15
	if len(inv.NatGateways) > 0 {
		duration += 120
	}
	if len(inv.LoadBalancers) > 0 {
		duration += 30
	}
	if len(inv.LambdaFuncs) > 0 || len(inv.ECSTasks) > 0 {
		duration += 25
	}
	if len(inv.ActiveENIs) > 0 {
		duration += 20
	}
	if len(inv.Subnets) > 0 {
		duration += 10
	}

	return &DryRunManifest{
		Target: target,
		BlastRadiusSummary: BlastRadiusSummary{
			TotalResourcesToDelete:   totalResourcesToDelete,
			TotalRulesToStrip:        totalRulesToStrip,
			EstimatedDurationSeconds: duration,
		},
		ExecutionPlan: tiers,
	}
}

// FormatJSON serializes the manifest to indented JSON.
func FormatJSON(manifest *DryRunManifest) ([]byte, error) {
	return json.MarshalIndent(manifest, "", "  ")
}

// FormatTerminal generates human-readable ASCII/ANSI output for the terminal.
func FormatTerminal(manifest *DryRunManifest) string {
	var sb strings.Builder

	sb.WriteString("================================================================================\n")
	sb.WriteString("                           VPCDRAIN DRY-RUN MANIFEST                            \n")
	sb.WriteString("================================================================================\n\n")

	sb.WriteString("🎯 TARGET ENVIRONMENT:\n")
	sb.WriteString(fmt.Sprintf("   VPC ID:     %s\n", manifest.Target.VpcID))
	sb.WriteString(fmt.Sprintf("   Region:     %s\n", manifest.Target.Region))
	sb.WriteString(fmt.Sprintf("   Account ID: %s\n", manifest.Target.AccountID))
	sb.WriteString("   Tags:       ")
	if len(manifest.Target.Tags) == 0 {
		sb.WriteString("(none)\n")
	} else {
		var tagPairs []string
		for k, v := range manifest.Target.Tags {
			tagPairs = append(tagPairs, fmt.Sprintf("%s=%s", k, v))
		}
		sb.WriteString(strings.Join(tagPairs, ", ") + "\n")
	}
	sb.WriteString("\n")

	sb.WriteString("📊 BLAST RADIUS SUMMARY:\n")
	sb.WriteString(fmt.Sprintf("   Total Resources to Delete:    %d\n", manifest.BlastRadiusSummary.TotalResourcesToDelete))
	sb.WriteString(fmt.Sprintf("   Total SG Rules to Strip:      %d\n", manifest.BlastRadiusSummary.TotalRulesToStrip))
	sb.WriteString(fmt.Sprintf("   Estimated Duration:           ~%d seconds\n\n", manifest.BlastRadiusSummary.EstimatedDurationSeconds))

	sb.WriteString("📋 8-TIER TOPOLOGICAL EXECUTION PLAN:\n")
	for _, tier := range manifest.ExecutionPlan {
		sb.WriteString(fmt.Sprintf("   [Tier %d] %s\n", tier.Tier, tier.Name))
		if len(tier.Resources) == 0 {
			sb.WriteString("      (no matching resources detected)\n")
		} else {
			for _, res := range tier.Resources {
				sb.WriteString(fmt.Sprintf("      • %-10s %-32s -> %s\n", res.Service, res.Action, res.ResourceID))
				if res.Details != "" {
					sb.WriteString(fmt.Sprintf("        └─ %s\n", res.Details))
				}
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("================================================================================\n")
	sb.WriteString("Dry run complete. No AWS resources were modified.\n")
	sb.WriteString("To execute real teardown, rerun with: --dry-run=false\n")
	sb.WriteString("================================================================================\n")

	return sb.String()
}
