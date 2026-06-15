package connect

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nagdevnihal/zttp/internal/cli/terminal"
)

const (
	ColorReset = "\033[0m"
	ColorRed   = "\033[31m"
	ColorGreen = "\033[32m"
	ColorCyan  = "\033[36m"
)

type loginForm struct {
	username string
	password string
	focus    int // 0: username, 1: password, 2: login, 3: exit
}

// drawLoginTUI launches a local graphical TUI for login.
// Returns (username, password, error). If user clicks Exit, returns ("exit", "", nil).
func drawLoginTUI() (string, string, error) {
	state, err := terminal.MakeRaw()
	if err != nil {
		return "", "", fmt.Errorf("failed to enter raw mode: %v", err)
	}
	defer terminal.Restore(state)

	form := &loginForm{}

	for {
		clearScreen()
		var out strings.Builder
		out.WriteString(fmt.Sprintf("%s=== ZTTP Secure Login ===%s\r\n\r\n", ColorCyan, ColorReset))

		drawField(&out, "Username", form.username, false, form.focus == 0)
		drawField(&out, "Password", form.password, true, form.focus == 1)

		out.WriteString("\r\n")
		if form.focus == 2 {
			out.WriteString(fmt.Sprintf("%s> [ Login ]%s\r\n", ColorGreen, ColorReset))
		} else {
			out.WriteString("  [ Login ]\r\n")
		}

		if form.focus == 3 {
			out.WriteString(fmt.Sprintf("%s> [ Exit  ]%s\r\n", ColorRed, ColorReset))
		} else {
			out.WriteString("  [ Exit  ]\r\n")
		}

		os.Stdout.Write([]byte(out.String()))

		key, err := readKey()
		if err != nil {
			return "", "", err
		}

		if key == "CTRL_C" {
			clearScreen()
			return "exit", "", nil
		}

		switch key {
		case "UP":
			if form.focus > 0 {
				form.focus--
			}
		case "DOWN":
			if form.focus < 3 {
				form.focus++
			}
		case "ENTER":
			if form.focus == 2 {
				if form.username == "" || form.password == "" {
					break
				}
				return form.username, form.password, nil
			} else if form.focus == 3 {
				clearScreen()
				return "exit", "", nil
			} else {
				form.focus++
			}
		case "BACKSPACE":
			if form.focus == 0 && len(form.username) > 0 {
				form.username = form.username[:len(form.username)-1]
			} else if form.focus == 1 && len(form.password) > 0 {
				form.password = form.password[:len(form.password)-1]
			}
		default:
			if len(key) == 1 && key != " " && key != "\t" {
				if form.focus == 0 {
					form.username += key
				} else if form.focus == 1 {
					form.password += key
				}
			}
		}
	}
}

func clearScreen() {
	os.Stdout.Write([]byte("\033[2J\033[H"))
}

func drawField(out *strings.Builder, label, val string, hidden, focused bool) {
	displayVal := val
	if hidden {
		displayVal = strings.Repeat("*", len(val))
	}
	if focused {
		out.WriteString(fmt.Sprintf("%s> %-8s: %s█%s\r\n", ColorGreen, label, displayVal, ColorReset))
	} else {
		out.WriteString(fmt.Sprintf("  %-8s: %s\r\n", label, displayVal))
	}
}

func readKey() (string, error) {
	buf := make([]byte, 1)
	_, err := os.Stdin.Read(buf)
	if err != nil {
		return "", err
	}

	if buf[0] == 0x1b {
		// Attempt to read next bytes for arrow keys
		b2 := make([]byte, 2)
		// Small delay to allow sequence to arrive
		time.Sleep(10 * time.Millisecond) 
		
		// Set non-blocking read
		oldState, _ := terminal.MakeRaw() // just in case
		defer terminal.Restore(oldState)
		
		ok := true
		if ok {
			os.Stdin.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, _ := io.ReadFull(os.Stdin, b2)
			os.Stdin.SetReadDeadline(time.Time{})
			if n == 2 && b2[0] == '[' {
				switch b2[1] {
				case 'A': return "UP", nil
				case 'B': return "DOWN", nil
				case 'C': return "RIGHT", nil
				case 'D': return "LEFT", nil
				}
			}
		}
		return "ESC", nil
	}

	if buf[0] == 13 || buf[0] == 10 {
		return "ENTER", nil
	}
	if buf[0] == 127 || buf[0] == 8 {
		return "BACKSPACE", nil
	}
	if buf[0] == 3 {
		return "CTRL_C", nil
	}

	return string(buf), nil
}
