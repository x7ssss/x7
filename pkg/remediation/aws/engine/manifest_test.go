package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildManifestAndJSONSerialization(t *testing.T) {
	inv := &VPCInventory{
		VpcID:   "vpc-0123456789abcdef0",
		Region:  "us-west-2",
		Account: "123456789012",
		Tags: map[string]string{
			"Ephemeral": "true",
			"PR":        "42",
		},
		ECSServices: []ECSServiceRef{
			{ClusterArn: "arn:aws:ecs:us-west-2:123456789012:cluster/test-cluster", ServiceArn: "arn:aws:ecs:us-west-2:123456789012:service/web", ServiceName: "web", DesiredCount: 2},
		},
		ECSTasks: []ECSTaskRef{
			{ClusterArn: "arn:aws:ecs:us-west-2:123456789012:cluster/test-cluster", TaskArn: "arn:aws:ecs:us-west-2:123456789012:task/task-1"},
		},
		LambdaFuncs: []LambdaFuncRef{
			{FunctionName: "vpc-worker", FunctionArn: "arn:aws:lambda:us-west-2:123456789012:function:vpc-worker"},
		},
		LoadBalancers: []LBRef{
			{LoadBalancerArn: "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-alb/123", LoadBalancerName: "my-alb", Type: "application"},
		},
		TargetGroups: []TargetGroupRef{
			{TargetGroupArn: "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/tg/123", TargetGroupName: "tg"},
		},
		VpcEndpoints: []string{"vpce-12345"},
		NatGateways: []NatGatewayRef{
			{NatGatewayID: "nat-001", State: "available", AllocationIDs: []string{"eipalloc-1"}},
		},
		TGWAttachments: []string{"tgw-attach-1"},
		PeeringConns:   []string{"pcx-1"},
		ElasticIPs:     []string{"eipalloc-1"},
		SecurityGroups: []SecurityGroupRef{
			{GroupID: "sg-default", GroupName: "default", IngressRulesCount: 1, EgressRulesCount: 1, IsDefault: true},
			{GroupID: "sg-custom-1", GroupName: "custom-sg-1", IngressRulesCount: 2, EgressRulesCount: 2, IsDefault: false},
			{GroupID: "sg-custom-2", GroupName: "custom-sg-2", IngressRulesCount: 1, EgressRulesCount: 1, IsDefault: false},
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

	manifest := BuildManifest(inv)

	// Verify Target
	if manifest.Target.VpcID != "vpc-0123456789abcdef0" {
		t.Errorf("Target VpcID = %s, want vpc-0123456789abcdef0", manifest.Target.VpcID)
	}
	if manifest.Target.AccountID != "123456789012" {
		t.Errorf("Target AccountID = %s, want 123456789012", manifest.Target.AccountID)
	}
	if manifest.Target.Region != "us-west-2" {
		t.Errorf("Target Region = %s, want us-west-2", manifest.Target.Region)
	}
	if manifest.Target.Tags["PR"] != "42" {
		t.Errorf("Target Tag PR = %s, want 42", manifest.Target.Tags["PR"])
	}

	// Verify Summary
	// Total rules to strip:
	// default: 1 + 1 = 2
	// custom-1: 2 + 2 = 4
	// custom-2: 1 + 1 = 2
	// total = 8
	if manifest.BlastRadiusSummary.TotalRulesToStrip != 8 {
		t.Errorf("TotalRulesToStrip = %d, want 8", manifest.BlastRadiusSummary.TotalRulesToStrip)
	}

	// Total resources to delete:
	// Tier 1: 1 ecs service + 1 ecs task + 1 lambda = 3
	// Tier 2: 1 lb + 1 tg + 1 vpce = 3
	// Tier 3: 1 nat + 1 tgw + 1 pcx = 3
	// Tier 4: 1 eip = 1
	// Tier 5: 0 resource deletions (only rule stripping)
	// Tier 6: 2 custom sgs + 1 custom rt = 3
	// Tier 7: 1 igw + 2 subnets = 3
	// Tier 8: 1 vpc = 1
	// Total = 3 + 3 + 3 + 1 + 3 + 3 + 1 = 17
	if manifest.BlastRadiusSummary.TotalResourcesToDelete != 17 {
		t.Errorf("TotalResourcesToDelete = %d, want 17", manifest.BlastRadiusSummary.TotalResourcesToDelete)
	}

	// Verify 8 tiers
	if len(manifest.ExecutionPlan) != 8 {
		t.Fatalf("ExecutionPlan length = %d, want 8", len(manifest.ExecutionPlan))
	}
	for i, tier := range manifest.ExecutionPlan {
		if tier.Tier != i+1 {
			t.Errorf("Tier index %d has tier number %d, want %d", i, tier.Tier, i+1)
		}
		if tier.Name == "" {
			t.Errorf("Tier %d has empty name", tier.Tier)
		}
	}

	// Test JSON serialization
	jsonBytes, err := FormatJSON(manifest)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	// Validate JSON schema compatibility
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal generated JSON: %v", err)
	}

	if _, ok := parsed["target"]; !ok {
		t.Error("JSON missing 'target' key")
	}
	if _, ok := parsed["blastRadiusSummary"]; !ok {
		t.Error("JSON missing 'blastRadiusSummary' key")
	}
	if _, ok := parsed["executionPlan"]; !ok {
		t.Error("JSON missing 'executionPlan' key")
	}

	// Check plan items schema
	planList := parsed["executionPlan"].([]interface{})
	if len(planList) != 8 {
		t.Errorf("expected 8 tiers in JSON plan, got %d", len(planList))
	}

	tier1 := planList[0].(map[string]interface{})
	resources := tier1["resources"].([]interface{})
	if len(resources) != 3 {
		t.Errorf("expected 3 resources in tier 1, got %d", len(resources))
	}
	res0 := resources[0].(map[string]interface{})
	if res0["resourceId"] == "" || res0["service"] == "" || res0["action"] == "" {
		t.Errorf("resource missing required fields: %v", res0)
	}
}

func TestFormatTerminal(t *testing.T) {
	inv := &VPCInventory{
		VpcID:   "vpc-test123",
		Region:  "us-east-1",
		Account: "111222333444",
		Tags:    map[string]string{"Ephemeral": "true"},
		Subnets: []string{"subnet-a"},
	}

	manifest := BuildManifest(inv)
	output := FormatTerminal(manifest)

	if !strings.Contains(output, "VPCDRAIN DRY-RUN MANIFEST") {
		t.Error("terminal output missing header banner")
	}
	if !strings.Contains(output, "vpc-test123") {
		t.Error("terminal output missing VPC ID")
	}
	if !strings.Contains(output, "111222333444") {
		t.Error("terminal output missing Account ID")
	}
	if !strings.Contains(output, "[Tier 1]") || !strings.Contains(output, "[Tier 8]") {
		t.Error("terminal output missing tier markers")
	}
}
