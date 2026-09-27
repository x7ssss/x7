package ui

import (
	"fmt"
	"io"
	"strings"
)

// TableColumn represents a column header and min width in a monospace table.
type TableColumn struct {
	Title string
	Width int
}

// Table renders monospace brutalist ASCII tables.
type Table struct {
	Columns []TableColumn
	Rows    [][]string
}

// NewTable initializes a new brutalist ASCII table.
func NewTable(columns ...TableColumn) *Table {
	return &Table{
		Columns: columns,
		Rows:    make([][]string, 0),
	}
}

// AddRow adds a row of string cells to the table.
func (t *Table) AddRow(cells ...string) {
	t.Rows = append(t.Rows, cells)
}

// Render renders the table to the provided writer.
func (t *Table) Render(w io.Writer) {
	if len(t.Columns) == 0 {
		return
	}

	widths := make([]int, len(t.Columns))
	for i, col := range t.Columns {
		widths[i] = len(col.Title)
		if col.Width > widths[i] {
			widths[i] = col.Width
		}
	}

	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Build separator line
	var sepParts []string
	for _, width := range widths {
		sepParts = append(sepParts, strings.Repeat("-", width+2))
	}
	border := "+" + strings.Join(sepParts, "+") + "+"

	// Render Header
	fmt.Fprintln(w, border)
	var headerParts []string
	for i, col := range t.Columns {
		headerParts = append(headerParts, fmt.Sprintf(" %-*s ", widths[i], col.Title))
	}
	fmt.Fprintf(w, "|%s|\n", strings.Join(headerParts, "|"))
	fmt.Fprintln(w, border)

	// Render Rows
	for _, row := range t.Rows {
		var rowParts []string
		for i := range t.Columns {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			rowParts = append(rowParts, fmt.Sprintf(" %-*s ", widths[i], val))
		}
		fmt.Fprintf(w, "|%s|\n", strings.Join(rowParts, "|"))
	}
	fmt.Fprintln(w, border)
}

// RenderCard prints a brutalist monospace status card with a title and key-value attributes.
func RenderCard(w io.Writer, title string, entries [][2]string) {
	width := 80
	border := "+" + strings.Repeat("-", width-2) + "+"
	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "| %-*s |\n", width-4, strings.ToUpper(title))
	fmt.Fprintln(w, "+"+strings.Repeat("-", width-2)+"+")
	for _, entry := range entries {
		line := fmt.Sprintf("%-20s: %s", entry[0], entry[1])
		if len(line) > width-4 {
			line = line[:width-7] + "..."
		}
		fmt.Fprintf(w, "| %-*s |\n", width-4, line)
	}
	fmt.Fprintln(w, border)
}
