package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLI_Helm_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"helm", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("x7 helm --help failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "inspect") || !strings.Contains(out, "recover") {
		t.Errorf("subcommands missing from helm help: %s", out)
	}
}

func TestCLI_Helm_Inspect_Validation(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"helm", "inspect"})

	err := RootCmd.Execute()
	if err == nil {
		t.Errorf("expected error when no release arg provided to helm inspect")
	}
}

func TestCLI_Helm_Recover_Validation(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"helm", "recover"})

	err := RootCmd.Execute()
	if err == nil {
		t.Errorf("expected error when no release arg provided to helm recover")
	}
}
