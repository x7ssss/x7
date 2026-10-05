package ui

import (
	"fmt"
	"io"
	"strings"
)

// Table renders minimalist brutalist tabular data.
type Table struct {
	headers []string
	rows    [][]string
}

// NewTable initializes a new brutalist table with headers.
func NewTable(headers ...string) *Table {
	upperHeaders := make([]string, len(headers))
	for i, h := range headers {
		upperHeaders[i] = strings.ToUpper(strings.TrimSpace(h))
	}
	return &Table{
		headers: upperHeaders,
		rows:    make([][]string, 0),
	}
}

// AddRow adds a row of values to the table.
func (t *Table) AddRow(cols ...string) {
	row := make([]string, len(cols))
	for i, c := range cols {
		row[i] = strings.TrimSpace(c)
	}
	t.rows = append(t.rows, row)
}

// Render writes the brutalist ASCII grid table to the writer.
func (t *Table) Render(w io.Writer) {
	colCount := len(t.headers)
	if colCount == 0 {
		return
	}

	widths := make([]int, colCount)
	for i, h := range t.headers {
		widths[i] = len(h)
	}

	for _, row := range t.rows {
		for i, col := range row {
			if i < colCount && len(col) > widths[i] {
				widths[i] = len(col)
			}
		}
	}

	// Build separator line: +---------------+---------------+
	buildSep := func() string {
		var sb strings.Builder
		sb.WriteString("+")
		for _, w := range widths {
			sb.WriteString(strings.Repeat("-", w+2))
			sb.WriteString("+")
		}
		return sb.String()
	}

	// Build row line: | HEADER      | STATUS        |
	buildRow := func(cols []string) string {
		var sb strings.Builder
		sb.WriteString("|")
		for i, w := range widths {
			val := ""
			if i < len(cols) {
				val = cols[i]
			}
			sb.WriteString(fmt.Sprintf(" %-*s |", w, val))
		}
		return sb.String()
	}

	sep := buildSep()
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, buildRow(t.headers))
	fmt.Fprintln(w, sep)

	if len(t.rows) == 0 {
		// Empty notice
		emptyMsg := "(no records found)"
		totalWidth := 0
		for _, w := range widths {
			totalWidth += w + 3
		}
		totalWidth--
		if totalWidth < len(emptyMsg)+2 {
			totalWidth = len(emptyMsg) + 2
		}
		fmt.Fprintf(w, "| %-*s |\n", totalWidth-2, emptyMsg)
		fmt.Fprintln(w, sep)
		return
	}

	for _, row := range t.rows {
		fmt.Fprintln(w, buildRow(row))
	}
	fmt.Fprintln(w, sep)
}

// RenderKeyValueBlock renders a brutalist key-value summary block.
func RenderKeyValueBlock(w io.Writer, title string, entries [][2]string) {
	upperTitle := strings.ToUpper(strings.TrimSpace(title))
	maxKeyLen := 0
	for _, e := range entries {
		if len(e[0]) > maxKeyLen {
			maxKeyLen = len(e[0])
		}
	}

	sepLen := maxKeyLen + 40
	if sepLen < len(upperTitle)+6 {
		sepLen = len(upperTitle) + 6
	}

	border := "+" + strings.Repeat("-", sepLen) + "+"
	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "| %-*s |\n", sepLen-2, upperTitle)
	fmt.Fprintln(w, border)

	for _, e := range entries {
		line := fmt.Sprintf("%-*s : %s", maxKeyLen, e[0], e[1])
		if len(line) > sepLen-2 {
			line = line[:sepLen-5] + "..."
		}
		fmt.Fprintf(w, "| %-*s |\n", sepLen-2, line)
	}
	fmt.Fprintln(w, border)
}
