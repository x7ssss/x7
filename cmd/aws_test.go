package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLI_AWS_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"aws", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("x7 aws --help failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "vpc-drain") {
		t.Errorf("subcommand vpc-drain missing from aws help: %s", out)
	}
}

func TestCLI_AWS_VPCDrain_Validation(t *testing.T) {
	// Missing --vpc-id
	awsVpcIDFlag = ""
	awsTagFlag = ""
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"aws", "vpc-drain", "--tag", "Ephemeral=true"})

	err := RootCmd.Execute()
	if err == nil {
		t.Errorf("expected error when --vpc-id is missing")
	}

	// Invalid VPC ID format
	awsVpcIDFlag = ""
	awsTagFlag = ""
	buf.Reset()
	RootCmd.SetArgs([]string{"aws", "vpc-drain", "--vpc-id", "invalid-id", "--tag", "Ephemeral=true"})
	err = RootCmd.Execute()
	if err == nil {
		t.Errorf("expected error when vpc-id does not start with vpc-")
	}

	// Missing --tag
	awsVpcIDFlag = ""
	awsTagFlag = ""
	buf.Reset()
	RootCmd.SetArgs([]string{"aws", "vpc-drain", "--vpc-id", "vpc-0123456789abcdef0"})
	err = RootCmd.Execute()
	if err == nil {
		t.Errorf("expected error when --tag is missing")
	}
}
