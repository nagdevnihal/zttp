// internal/cli/terminal/terminal.go
package terminal

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// Prompt prints a prompt and reads user input.
// If hidden=true, input is not echoed (for passwords).
func Prompt(prompt string, hidden bool) (string, error) {
	fmt.Print(prompt)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		var input string
		fmt.Scanln(&input)
		return input, nil
	}

	if hidden {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // print newline since hidden input doesn't
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	var input string
	_, err := fmt.Scanln(&input)
	return input, err
}

// GetSize returns the current terminal window dimensions.
func GetSize() (width, height int, err error) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	return w, h, err
}

// MakeRaw sets the terminal to raw mode (no line buffering, no echo).
// Required for full PTY passthrough — lets ANSI codes flow through unmodified.
func MakeRaw() (*term.State, error) {
	return term.MakeRaw(int(os.Stdin.Fd()))
}

// Restore restores the terminal to its previous state.
// Always called via defer to prevent a stuck raw terminal on crash.
func Restore(state *term.State) {
	if state != nil {
		_ = term.Restore(int(os.Stdin.Fd()), state)
	}
}
