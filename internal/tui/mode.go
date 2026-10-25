package tui

import (
	"os"

	"golang.org/x/term"
)

var enabled = true

// SetHeadless disables all TUI output (plain text mode for automation).
func SetHeadless(headless bool) {
	enabled = !headless
}

// IsEnabled returns whether TUI mode is active.
func IsEnabled() bool {
	return enabled
}

// AutoDetect sets TUI mode based on whether stderr is a terminal.
// Call this at startup before any TUI output.
func AutoDetect() {
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		enabled = false
	}
}
