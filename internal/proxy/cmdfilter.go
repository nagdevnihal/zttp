// internal/proxy/cmdfilter.go
// Command filter stream interceptor.
//
// Operates at the stdin goroutine level, scanning the stream for newline-terminated
// commands before forwarding them to the backend SSH session.
package proxy

import (
	"bytes"
	"io"
	"strings"

	"github.com/nagdevnihal/zttp/internal/rbac"
)

// commandFilterWriter wraps a writer and intercepts stdin to block prohibited commands.
// It parses the stream into lines, checks each line against the RBAC policy,
// and drops prohibited commands while writing an error message back to the client.
type commandFilterWriter struct {
	target      io.Writer
	clientW     io.Writer // used to write policy-violation errors back to the user's terminal
	allowedCmds []string  // the whitelist for this session (nil means full shell)
	buf         bytes.Buffer
}

func newCommandFilterWriter(target io.Writer, clientW io.Writer, allowedCmds []string) *commandFilterWriter {
	return &commandFilterWriter{
		target:      target,
		clientW:     clientW,
		allowedCmds: allowedCmds,
	}
}

func (f *commandFilterWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		// Handle backspace/delete for our internal buffer
		if b == 127 || b == 8 {
			if f.buf.Len() > 0 {
				f.buf.Truncate(f.buf.Len() - 1)
			}
			// Forward the backspace instantly
			if _, err := f.target.Write([]byte{b}); err != nil {
				return 0, err
			}
			continue
		}

		if b == '\n' || b == '\r' {
			rawLine := f.buf.String()
			f.buf.Reset()

			cleanLine := strings.TrimSpace(rawLine)
			if cleanLine != "" {
				if !rbac.IsCommandAllowed(cleanLine, f.allowedCmds) {
					isMux := false
					base := extractBase(cleanLine)
					for _, blocked := range rbac.BlockedMultiplexers {
						if strings.EqualFold(base, blocked) {
							isMux = true
							break
						}
					}

					var errMsg string
					if isMux {
						errMsg = rbac.MultiplexerViolationMessage(cleanLine)
					} else {
						errMsg = rbac.WhitelistViolationMessage(cleanLine)
					}

					// Intercept the command! Do NOT forward the \r.
					// Instead, send Ctrl+C (\x03) to the target server to cancel the line.
					_, _ = f.target.Write([]byte{0x03})
					
					// Write the error message back to the client
					_, _ = f.clientW.Write([]byte(errMsg))
					continue
				}
			}

			// Command is allowed (or empty) — forward the Enter key
			if _, err := f.target.Write([]byte{b}); err != nil {
				return 0, err
			}
			continue
		}

		// Normal character: append to our buffer and forward instantly!
		f.buf.WriteByte(b)
		if _, err := f.target.Write([]byte{b}); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func extractBase(cmdLine string) string {
	fields := strings.Fields(strings.TrimSpace(cmdLine))
	if len(fields) == 0 {
		return ""
	}
	binary := fields[0]
	if idx := strings.LastIndex(binary, "/"); idx >= 0 {
		binary = binary[idx+1:]
	}
	return binary
}
