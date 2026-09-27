package triage_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoEmDashes(t *testing.T) {
	err := filepath.Walk("../..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only check source files and markdown
		ext := filepath.Ext(path)
		if ext != ".go" && ext != ".md" && ext != ".ps1" && ext != ".mod" && ext != ".sum" && info.Name() != "Makefile" {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		content := string(data)
		// Check for em dash (U+2014) and en dash (U+2013)
		if strings.Contains(content, "\u2014") {
			t.Errorf("file %s contains em dash (\\u2014)", path)
		}
		if strings.Contains(content, "\u2013") {
			t.Errorf("file %s contains en dash (\\u2013)", path)
		}

		return nil
	})

	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
}
