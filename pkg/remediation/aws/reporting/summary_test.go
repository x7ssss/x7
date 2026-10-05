package reporting

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCalculateSavings(t *testing.T) {
	resources := SweptResources{
		VpcID:         "vpc-0123456789abcdef0",
		Region:        "us-east-1",
		AccountID:     "123456789012",
		NatGateways:   2,
		ElasticIPs:    2,
		LoadBalancers: 1,
		EC2Instances:  1,
		VpcEndpoints:  2,
	}

	savings := CalculateSavings(resources)

	// Expected:
	// NAT GW: 2 * 32.85 = 65.70
	// EIP:    2 * 3.65  = 7.30
	// ALB:    1 * 18.25 = 18.25
	// EC2:    1 * 40.00 = 40.00
	// VPCE:   2 * 7.30  = 14.60
	// Total:  65.70 + 7.30 + 18.25 + 40.00 + 14.60 = 145.85
	expectedMonthly := 145.85
	expectedAnnual := expectedMonthly * 12.0

	if math.Abs(savings.TotalMonthly-expectedMonthly) > 0.001 {
		t.Errorf("TotalMonthly = %.2f; want %.2f", savings.TotalMonthly, expectedMonthly)
	}

	if math.Abs(savings.TotalAnnualized-expectedAnnual) > 0.001 {
		t.Errorf("TotalAnnualized = %.2f; want %.2f", savings.TotalAnnualized, expectedAnnual)
	}

	if len(savings.Items) != 5 {
		t.Errorf("expected 5 items, got %d", len(savings.Items))
	}
}

func TestGenerateMarkdownSummary(t *testing.T) {
	resources := SweptResources{
		VpcID:            "vpc-test-999",
		Region:           "eu-west-1",
		AccountID:        "999888777666",
		NatGateways:      1,
		ElasticIPs:       1,
		Subnets:          3,
		SecurityGroups:   2,
		RouteTables:      2,
		InternetGateways: 1,
		DurationSeconds:  45,
	}

	markdown := GenerateMarkdownSummary(resources)

	if !strings.Contains(markdown, "FinOps VPC Teardown Summary") {
		t.Error("missing title")
	}
	if !strings.Contains(markdown, "vpc-test-999") {
		t.Error("missing VPC ID")
	}
	if !strings.Contains(markdown, "eu-west-1") {
		t.Error("missing region")
	}
	if !strings.Contains(markdown, "999888777666") {
		t.Error("missing account ID")
	}
	if !strings.Contains(markdown, "NAT Gateways") {
		t.Error("missing NAT Gateways category")
	}
	if !strings.Contains(markdown, "$32.85") {
		t.Error("missing NAT Gateway monthly rate")
	}
	if !strings.Contains(markdown, "Subnets") {
		t.Error("missing Subnets section")
	}
}

func TestEmitGitHubSummary(t *testing.T) {
	tmpDir := t.TempDir()
	summaryFile := filepath.Join(tmpDir, "github_step_summary.md")

	resources := SweptResources{
		VpcID:       "vpc-gh-action",
		Region:      "us-west-2",
		AccountID:   "111222333444",
		NatGateways: 1,
		Subnets:     2,
	}

	err := EmitGitHubSummary(resources, summaryFile)
	if err != nil {
		t.Fatalf("EmitGitHubSummary failed: %v", err)
	}

	data, err := os.ReadFile(summaryFile)
	if err != nil {
		t.Fatalf("failed to read written summary file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "vpc-gh-action") {
		t.Error("summary file does not contain VPC ID")
	}
	if !strings.Contains(content, "FinOps VPC Teardown Summary") {
		t.Error("summary file does not contain title")
	}
}
