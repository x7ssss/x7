package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLI_K8s_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"k8s", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("x7 k8s --help failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "diagnose") || !strings.Contains(out, "unstick") {
		t.Errorf("subcommands missing from k8s help: %s", out)
	}
}

func TestCLI_K8s_Diagnose_Validation(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"k8s", "diagnose"})

	err := RootCmd.Execute()
	if err == nil {
		t.Errorf("expected error when no namespace provided to k8s diagnose")
	}
}

func TestCLI_K8s_Unstick_Validation(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"k8s", "unstick"})

	err := RootCmd.Execute()
	if err == nil {
		t.Errorf("expected error when no namespace provided to k8s unstick")
	}
}
