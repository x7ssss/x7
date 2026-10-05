package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// FormatJSON serializes any data structure into an indented JSON byte slice.
func FormatJSON(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// PrintJSON formats and prints an object as indented JSON to the provided writer.
func PrintJSON(w io.Writer, v interface{}) error {
	data, err := FormatJSON(v)
	if err != nil {
		return fmt.Errorf("json serialization failed: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// PrintJSONStdout prints an object as indented JSON directly to os.Stdout.
func PrintJSONStdout(v interface{}) error {
	return PrintJSON(os.Stdout, v)
}
