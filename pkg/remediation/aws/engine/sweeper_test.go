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
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
)

type mockEC2SweeperClient struct {
	awsclient.EC2Client
	mu                  sync.Mutex
	revokedIngress      map[string]int
	revokedEgress       map[string]int
	deletedSGs          []string
	disassociatedRTs    []string
	deletedRTs          []string
	detachedIGWs        []string
	deletedIGWs         []string
	deletedSubnets      []string
	deletedVPCs         []string
	deletedNatGWs       []string
	releasedEIPs        []string
	deletedTGWAttaches  []string
	deletedPeeringConns []string
	deletedVPCEndpoints []string
	deleteVpcAttempts   int
}

func newMockEC2SweeperClient() *mockEC2SweeperClient {
	return &mockEC2SweeperClient{
		revokedIngress: make(map[string]int),
		revokedEgress:  make(map[string]int),
	}
}

func (m *mockEC2SweeperClient) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	// Return circular dependencies: sg-web and sg-db referencing each other
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
				GroupId:   aws.String("sg-web"),
				GroupName: aws.String("web-tier"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol:       aws.String("tcp"),
						FromPort:         aws.Int32(80),
						ToPort:           aws.Int32(80),
						UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-db")}},
					},
				},
				IpPermissionsEgress: []ec2types.IpPermission{
					{
						IpProtocol:       aws.String("tcp"),
						FromPort:         aws.Int32(5432),
						ToPort:           aws.Int32(5432),
						UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-db")}},
					},
				},
			},
			{
				GroupId:   aws.String("sg-db"),
				GroupName: aws.String("db-tier"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol:       aws.String("tcp"),
						FromPort:         aws.Int32(5432),
						ToPort:           aws.Int32(5432),
						UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-web")}},
					},
				},
				IpPermissionsEgress: []ec2types.IpPermission{
					{
						IpProtocol:       aws.String("tcp"),
						FromPort:         aws.Int32(80),
						ToPort:           aws.Int32(80),
						UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-web")}},
					},
				},
			},
		},
	}, nil
}

func (m *mockEC2SweeperClient) RevokeSecurityGroupIngress(ctx context.Context, params *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sgID := aws.ToString(params.GroupId)
	m.revokedIngress[sgID] += len(params.IpPermissions)
	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}

func (m *mockEC2SweeperClient) RevokeSecurityGroupEgress(ctx context.Context, params *ec2.RevokeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sgID := aws.ToString(params.GroupId)
	m.revokedEgress[sgID] += len(params.IpPermissions)
	return &ec2.RevokeSecurityGroupEgressOutput{}, nil
}

func (m *mockEC2SweeperClient) DeleteSecurityGroup(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sgID := aws.ToString(params.GroupId)
	m.deletedSGs = append(m.deletedSGs, sgID)
	return &ec2.DeleteSecurityGroupOutput{}, nil
}

func (m *mockEC2SweeperClient) DisassociateRouteTable(ctx context.Context, params *ec2.DisassociateRouteTableInput, optFns ...func(*ec2.Options)) (*ec2.DisassociateRouteTableOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disassociatedRTs = append(m.disassociatedRTs, aws.ToString(params.AssociationId))
	return &ec2.DisassociateRouteTableOutput{}, nil
}

func (m *mockEC2SweeperClient) DeleteRouteTable(ctx context.Context, params *ec2.DeleteRouteTableInput, optFns ...func(*ec2.Options)) (*ec2.DeleteRouteTableOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedRTs = append(m.deletedRTs, aws.ToString(params.RouteTableId))
	return &ec2.DeleteRouteTableOutput{}, nil
}

func (m *mockEC2SweeperClient) DetachInternetGateway(ctx context.Context, params *ec2.DetachInternetGatewayInput, optFns ...func(*ec2.Options)) (*ec2.DetachInternetGatewayOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.detachedIGWs = append(m.detachedIGWs, aws.ToString(params.InternetGatewayId))
	return &ec2.DetachInternetGatewayOutput{}, nil
}

func (m *mockEC2SweeperClient) DeleteInternetGateway(ctx context.Context, params *ec2.DeleteInternetGatewayInput, optFns ...func(*ec2.Options)) (*ec2.DeleteInternetGatewayOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedIGWs = append(m.deletedIGWs, aws.ToString(params.InternetGatewayId))
	return &ec2.DeleteInternetGatewayOutput{}, nil
}

func (m *mockEC2SweeperClient) DeleteSubnet(ctx context.Context, params *ec2.DeleteSubnetInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSubnetOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedSubnets = append(m.deletedSubnets, aws.ToString(params.SubnetId))
	return &ec2.DeleteSubnetOutput{}, nil
}

func (m *mockEC2SweeperClient) DeleteVpc(ctx context.Context, params *ec2.DeleteVpcInput, optFns ...func(*ec2.Options)) (*ec2.DeleteVpcOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteVpcAttempts++
	m.deletedVPCs = append(m.deletedVPCs, aws.ToString(params.VpcId))
	return &ec2.DeleteVpcOutput{}, nil
}

func (m *mockEC2SweeperClient) DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []ec2types.NetworkInterface{}}, nil
}

func (m *mockEC2SweeperClient) DescribeNatGateways(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	return &ec2.DescribeNatGatewaysOutput{
		NatGateways: []ec2types.NatGateway{
			{NatGatewayId: aws.String("nat-01"), State: ec2types.NatGatewayStateDeleted},
		},
	}, nil
}

func (m *mockEC2SweeperClient) DeleteNatGateway(ctx context.Context, params *ec2.DeleteNatGatewayInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNatGatewayOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedNatGWs = append(m.deletedNatGWs, aws.ToString(params.NatGatewayId))
	return &ec2.DeleteNatGatewayOutput{}, nil
}

func (m *mockEC2SweeperClient) ReleaseAddress(ctx context.Context, params *ec2.ReleaseAddressInput, optFns ...func(*ec2.Options)) (*ec2.ReleaseAddressOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releasedEIPs = append(m.releasedEIPs, aws.ToString(params.AllocationId))
	return &ec2.ReleaseAddressOutput{}, nil
}

func (m *mockEC2SweeperClient) DeleteTransitGatewayVpcAttachment(ctx context.Context, params *ec2.DeleteTransitGatewayVpcAttachmentInput, optFns ...func(*ec2.Options)) (*ec2.DeleteTransitGatewayVpcAttachmentOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedTGWAttaches = append(m.deletedTGWAttaches, aws.ToString(params.TransitGatewayAttachmentId))
	return &ec2.DeleteTransitGatewayVpcAttachmentOutput{}, nil
}

func (m *mockEC2SweeperClient) DeleteVpcPeeringConnection(ctx context.Context, params *ec2.DeleteVpcPeeringConnectionInput, optFns ...func(*ec2.Options)) (*ec2.DeleteVpcPeeringConnectionOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedPeeringConns = append(m.deletedPeeringConns, aws.ToString(params.VpcPeeringConnectionId))
	return &ec2.DeleteVpcPeeringConnectionOutput{}, nil
}

func (m *mockEC2SweeperClient) DeleteVpcEndpoints(ctx context.Context, params *ec2.DeleteVpcEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DeleteVpcEndpointsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedVPCEndpoints = append(m.deletedVPCEndpoints, params.VpcEndpointIds...)
	return &ec2.DeleteVpcEndpointsOutput{}, nil
}

type mockELBv2SweeperClient struct {
	awsclient.ELBv2Client
	deletedLBs []string
	deletedTGs []string
}

func (m *mockELBv2SweeperClient) DeleteLoadBalancer(ctx context.Context, params *elasticloadbalancingv2.DeleteLoadBalancerInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DeleteLoadBalancerOutput, error) {
	m.deletedLBs = append(m.deletedLBs, aws.ToString(params.LoadBalancerArn))
	return &elasticloadbalancingv2.DeleteLoadBalancerOutput{}, nil
}

func (m *mockELBv2SweeperClient) DeleteTargetGroup(ctx context.Context, params *elasticloadbalancingv2.DeleteTargetGroupInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DeleteTargetGroupOutput, error) {
	m.deletedTGs = append(m.deletedTGs, aws.ToString(params.TargetGroupArn))
	return &elasticloadbalancingv2.DeleteTargetGroupOutput{}, nil
}

type mockECSSweeperClient struct {
	awsclient.ECSClient
	updatedServices []string
	stoppedTasks    []string
}

func (m *mockECSSweeperClient) UpdateService(ctx context.Context, params *ecs.UpdateServiceInput, optFns ...func(*ecs.Options)) (*ecs.UpdateServiceOutput, error) {
	m.updatedServices = append(m.updatedServices, aws.ToString(params.Service))
	return &ecs.UpdateServiceOutput{}, nil
}

func (m *mockECSSweeperClient) StopTask(ctx context.Context, params *ecs.StopTaskInput, optFns ...func(*ecs.Options)) (*ecs.StopTaskOutput, error) {
	m.stoppedTasks = append(m.stoppedTasks, aws.ToString(params.Task))
	return &ecs.StopTaskOutput{}, nil
}

type mockLambdaSweeperClient struct {
	awsclient.LambdaClient
	updatedFuncs []string
}

func (m *mockLambdaSweeperClient) UpdateFunctionConfiguration(ctx context.Context, params *lambda.UpdateFunctionConfigurationInput, optFns ...func(*lambda.Options)) (*lambda.UpdateFunctionConfigurationOutput, error) {
	m.updatedFuncs = append(m.updatedFuncs, aws.ToString(params.FunctionName))
	return &lambda.UpdateFunctionConfigurationOutput{}, nil
}

func TestCircularSecurityGroupStripping(t *testing.T) {
	ctx := context.Background()
	log := logger.NewCustomLogger(&strings.Builder{}, &strings.Builder{}, logger.LevelDebug, false)
	ec2Mock := newMockEC2SweeperClient()

	clients := &awsclient.Clients{
		EC2: ec2Mock,
	}

	sweeper := NewSweeper(clients, FastSweeperOptions(log))

	inv := &VPCInventory{
		VpcID: "vpc-test-circular",
	}

	err := sweeper.ExecuteTier5SGCycleStripping(ctx, inv)
	if err != nil {
		t.Fatalf("ExecuteTier5SGCycleStripping failed: %v", err)
	}

	// Verify that ingress and egress were revoked for all 3 groups (sg-default, sg-web, sg-db)
	if ec2Mock.revokedIngress["sg-web"] != 1 {
		t.Errorf("expected 1 ingress rule revoked on sg-web, got %d", ec2Mock.revokedIngress["sg-web"])
	}
	if ec2Mock.revokedEgress["sg-web"] != 1 {
		t.Errorf("expected 1 egress rule revoked on sg-web, got %d", ec2Mock.revokedEgress["sg-web"])
	}
	if ec2Mock.revokedIngress["sg-db"] != 1 {
		t.Errorf("expected 1 ingress rule revoked on sg-db, got %d", ec2Mock.revokedIngress["sg-db"])
	}
	if ec2Mock.revokedEgress["sg-db"] != 1 {
		t.Errorf("expected 1 egress rule revoked on sg-db, got %d", ec2Mock.revokedEgress["sg-db"])
	}
}

func TestFull8TierTeardown(t *testing.T) {
	ctx := context.Background()
	log := logger.NewCustomLogger(&strings.Builder{}, &strings.Builder{}, logger.LevelDebug, false)

	ec2Mock := newMockEC2SweeperClient()
	elbMock := &mockELBv2SweeperClient{}
	ecsMock := &mockECSSweeperClient{}
	lambdaMock := &mockLambdaSweeperClient{}

	clients := &awsclient.Clients{
		EC2:    ec2Mock,
		ELBv2:  elbMock,
		ECS:    ecsMock,
		Lambda: lambdaMock,
	}

	opts := FastSweeperOptions(log)
	opts.RetryInterval = 1 * time.Millisecond
	sweeper := NewSweeper(clients, opts)

	inv := &VPCInventory{
		VpcID:   "vpc-0123456789abcdef0",
		Region:  "us-west-2",
		Account: "123456789012",
		ECSServices: []ECSServiceRef{
			{ClusterArn: "cluster-1", ServiceArn: "svc-1", ServiceName: "web"},
		},
		ECSTasks: []ECSTaskRef{
			{ClusterArn: "cluster-1", TaskArn: "task-1"},
		},
		LambdaFuncs: []LambdaFuncRef{
			{FunctionName: "fn-worker"},
		},
		LoadBalancers: []LBRef{
			{LoadBalancerArn: "arn:alb-1", Type: "application"},
		},
		TargetGroups: []TargetGroupRef{
			{TargetGroupArn: "arn:tg-1"},
		},
		VpcEndpoints: []string{"vpce-1"},
		NatGateways: []NatGatewayRef{
			{NatGatewayID: "nat-01", State: "available", AllocationIDs: []string{"eipalloc-1"}},
		},
		TGWAttachments: []string{"tgw-attach-1"},
		PeeringConns:   []string{"pcx-1"},
		ElasticIPs:     []string{"eipalloc-1"},
		SecurityGroups: []SecurityGroupRef{
			{GroupID: "sg-default", GroupName: "default", IsDefault: true},
			{GroupID: "sg-custom-1", GroupName: "custom-sg-1", IsDefault: false},
		},
		RouteTables: []RouteTableRef{
			{RouteTableID: "rtb-main", IsMain: true},
			{
				RouteTableID: "rtb-custom",
				IsMain:       false,
				Associations: []RouteTableAssocRef{
					{AssociationID: "rtbassoc-1", SubnetID: "subnet-1", Main: false},
				},
			},
		},
		InternetGateways: []string{"igw-1"},
		Subnets:          []string{"subnet-1", "subnet-2"},
	}

	err := sweeper.Execute(ctx, inv)
	if err != nil {
		t.Fatalf("Sweeper.Execute failed: %v", err)
	}

	// 1. Tier 1 Compute Verification
	if len(ecsMock.updatedServices) != 1 || ecsMock.updatedServices[0] != "svc-1" {
		t.Errorf("ECS service not scaled down: %v", ecsMock.updatedServices)
	}
	if len(ecsMock.stoppedTasks) != 1 || ecsMock.stoppedTasks[0] != "task-1" {
		t.Errorf("ECS task not stopped: %v", ecsMock.stoppedTasks)
	}
	if len(lambdaMock.updatedFuncs) != 1 || lambdaMock.updatedFuncs[0] != "fn-worker" {
		t.Errorf("Lambda VPC config not detached: %v", lambdaMock.updatedFuncs)
	}

	// 2. Tier 2 Ingress Verification
	if len(elbMock.deletedLBs) != 1 || elbMock.deletedLBs[0] != "arn:alb-1" {
		t.Errorf("ALB not deleted: %v", elbMock.deletedLBs)
	}
	if len(elbMock.deletedTGs) != 1 || elbMock.deletedTGs[0] != "arn:tg-1" {
		t.Errorf("TG not deleted: %v", elbMock.deletedTGs)
	}
	if len(ec2Mock.deletedVPCEndpoints) != 1 || ec2Mock.deletedVPCEndpoints[0] != "vpce-1" {
		t.Errorf("VPC endpoint not deleted: %v", ec2Mock.deletedVPCEndpoints)
	}

	// 3. Tier 3 Egress Verification
	if len(ec2Mock.deletedNatGWs) != 1 || ec2Mock.deletedNatGWs[0] != "nat-01" {
		t.Errorf("NAT Gateway not deleted: %v", ec2Mock.deletedNatGWs)
	}
	if len(ec2Mock.deletedTGWAttaches) != 1 || ec2Mock.deletedTGWAttaches[0] != "tgw-attach-1" {
		t.Errorf("TGW Attachment not deleted: %v", ec2Mock.deletedTGWAttaches)
	}
	if len(ec2Mock.deletedPeeringConns) != 1 || ec2Mock.deletedPeeringConns[0] != "pcx-1" {
		t.Errorf("Peering connection not deleted: %v", ec2Mock.deletedPeeringConns)
	}

	// 4. Tier 4 Elastic IPs Verification
	if len(ec2Mock.releasedEIPs) != 1 || ec2Mock.releasedEIPs[0] != "eipalloc-1" {
		t.Errorf("EIP not released: %v", ec2Mock.releasedEIPs)
	}

	// 5. Tier 6 Custom SGs and Route Tables Verification
	// Must delete custom SG, never default SG!
	if len(ec2Mock.deletedSGs) != 1 || ec2Mock.deletedSGs[0] != "sg-custom-1" {
		t.Errorf("Custom SG not deleted correctly: %v", ec2Mock.deletedSGs)
	}
	for _, sg := range ec2Mock.deletedSGs {
		if sg == "sg-default" {
			t.Error("Default security group was deleted; it must be skipped!")
		}
	}

	// Must disassociate and delete custom route table, never main route table!
	if len(ec2Mock.disassociatedRTs) != 1 || ec2Mock.disassociatedRTs[0] != "rtbassoc-1" {
		t.Errorf("Custom RT association not disassociated: %v", ec2Mock.disassociatedRTs)
	}
	if len(ec2Mock.deletedRTs) != 1 || ec2Mock.deletedRTs[0] != "rtb-custom" {
		t.Errorf("Custom RT not deleted: %v", ec2Mock.deletedRTs)
	}
	for _, rt := range ec2Mock.deletedRTs {
		if rt == "rtb-main" {
			t.Error("Main route table was deleted; it must be skipped!")
		}
	}

	// 6. Tier 7 Gateways & Subnets Verification
	if len(ec2Mock.detachedIGWs) != 1 || ec2Mock.detachedIGWs[0] != "igw-1" {
		t.Errorf("IGW not detached: %v", ec2Mock.detachedIGWs)
	}
	if len(ec2Mock.deletedIGWs) != 1 || ec2Mock.deletedIGWs[0] != "igw-1" {
		t.Errorf("IGW not deleted: %v", ec2Mock.deletedIGWs)
	}
	if len(ec2Mock.deletedSubnets) != 2 {
		t.Errorf("Expected 2 subnets deleted, got %d: %v", len(ec2Mock.deletedSubnets), ec2Mock.deletedSubnets)
	}

	// 7. Tier 8 VPC Deletion Verification
	if len(ec2Mock.deletedVPCs) != 1 || ec2Mock.deletedVPCs[0] != "vpc-0123456789abcdef0" {
		t.Errorf("VPC not deleted: %v", ec2Mock.deletedVPCs)
	}
}
