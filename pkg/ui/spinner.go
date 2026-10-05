package ui

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/x7ssss/x7/pkg/safety"
)

// Spinner represents a terminal progress spinner for long-running operations.
type Spinner struct {
	mu     sync.Mutex
	w      io.Writer
	msg    string
	active bool
	stopCh chan struct{}
}

// NewSpinner constructs a new terminal spinner.
func NewSpinner(msg string) *Spinner {
	return &Spinner{
		w:      os.Stderr,
		msg:    msg,
		stopCh: make(chan struct{}),
	}
}

// Start begins animating the terminal spinner.
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.active || !safety.IsTerminal(os.Stderr) {
		s.mu.Unlock()
		if !safety.IsTerminal(os.Stderr) && s.msg != "" {
			fmt.Fprintf(s.w, "%s...\n", s.msg)
		}
		return
	}
	s.active = true
	s.mu.Unlock()

	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	go func() {
		idx := 0
		for {
			select {
			case <-s.stopCh:
				return
			default:
				s.mu.Lock()
				msg := s.msg
				s.mu.Unlock()
				fmt.Fprintf(s.w, "\r\033[K%s %s", Colorize(ColorCyan+ColorBold, frames[idx]), msg)
				idx = (idx + 1) % len(frames)
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

// UpdateMessage changes the active message displayed beside the spinner.
func (s *Spinner) UpdateMessage(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msg = msg
}

// Stop stops the spinner animation and clears the line.
func (s *Spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return
	}
	s.active = false
	close(s.stopCh)
	fmt.Fprintf(s.w, "\r\033[K")
}

// Success stops the spinner and displays a green success mark.
func (s *Spinner) Success(msg string) {
	s.Stop()
	if msg == "" {
		s.mu.Lock()
		msg = s.msg
		s.mu.Unlock()
	}
	fmt.Fprintf(s.w, "%s %s\n", Colorize(ColorGreen+ColorBold, "✔"), msg)
}

// Fail stops the spinner and displays a red failure mark.
func (s *Spinner) Fail(msg string) {
	s.Stop()
	if msg == "" {
		s.mu.Lock()
		msg = s.msg
		s.mu.Unlock()
	}
	fmt.Fprintf(s.w, "%s %s\n", Colorize(ColorRed+ColorBold, "✖"), msg)
}
