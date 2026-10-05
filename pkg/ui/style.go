package ui

import (
	"os"

	"github.com/x7ssss/x7/pkg/safety"
)

// ANSI color escapes
const (
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

// UseColor determines whether color output should be enabled.
func UseColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return safety.IsTerminal(os.Stdout)
}

// Colorize wraps text in ANSI color codes if terminal colors are supported.
func Colorize(color, text string) string {
	if !UseColor() {
		return text
	}
	return color + text + ColorReset
}

// Status badges
func BadgePass(text string) string {
	if text == "" {
		text = "PASS"
	}
	return Colorize(ColorGreen+ColorBold, "["+text+"]")
}

func BadgeFail(text string) string {
	if text == "" {
		text = "FAIL"
	}
	return Colorize(ColorRed+ColorBold, "["+text+"]")
}

func BadgeWarn(text string) string {
	if text == "" {
		text = "WARN"
	}
	return Colorize(ColorYellow+ColorBold, "["+text+"]")
}

func BadgeInfo(text string) string {
	if text == "" {
		text = "INFO"
	}
	return Colorize(ColorCyan+ColorBold, "["+text+"]")
}
