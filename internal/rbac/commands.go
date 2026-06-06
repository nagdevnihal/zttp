// internal/rbac/commands.go
// Command filtering for RBAC-restricted sessions.
//
// Two layers of enforcement:
//
//  1. Multiplexer block (always-on): tmux, screen, nohup, disown, setsid are
//     unconditionally denied. These create orphan processes that escape the
//     ZTTP audit boundary — the session recorder loses visibility the moment
//     one of these runs.
//
//  2. Command whitelist (optional): if policy.allowed_commands is non-nil,
//     only those specific binaries are permitted. Used for auditor/readonly roles.
//
// Both layers operate on the base binary name — stripping path prefix and
// handling both "/usr/bin/tmux" and "tmux" identically.
package rbac

import "strings"

// BlockedMultiplexers are always denied, regardless of any policy override.
// Reason: they fork child processes that survive the parent shell's exit,
// creating sessions that the .ttyrec audit recorder cannot observe.
var BlockedMultiplexers = []string{
	"tmux",
	"screen",
	"nohup",
	"disown",
	"setsid",
	"byobu",
	"dtach",
}

// IsCommandAllowed returns true if the given command line is permitted for this session.
//
// Parameters:
//   - cmdLine: the raw command string as typed by the user (e.g., "/usr/bin/tmux -s main")
//   - allowedCmds: nil means full shell (only multiplexers are blocked);
//     non-nil is the explicit whitelist from policy.allowed_commands
func IsCommandAllowed(cmdLine string, allowedCmds []string) bool {
	base := extractBinaryName(cmdLine)
	if base == "" {
		return true // empty line — allow (shell will ignore it too)
	}

	// Layer 1: Always block multiplexers
	for _, blocked := range BlockedMultiplexers {
		if strings.EqualFold(base, blocked) {
			return false
		}
	}

	// Layer 2: If no command whitelist, permit everything else
	if len(allowedCmds) == 0 {
		return true
	}

	// Layer 3: Check against the role's command whitelist
	for _, allowed := range allowedCmds {
		if strings.EqualFold(base, allowed) {
			return true
		}
	}

	return false
}

// MultiplexerViolationMessage returns the error message shown to the user
// when a blocked multiplexer is attempted.
func MultiplexerViolationMessage(cmd string) string {
	return "\r\n\033[31m[ZTTP Policy]\033[0m Command '" + extractBinaryName(cmd) +
		"' is prohibited. Long-running tasks must use CI/CD pipelines.\r\n"
}

// WhitelistViolationMessage returns the error message shown when a non-whitelisted
// command is attempted in a restricted session.
func WhitelistViolationMessage(cmd string) string {
	return "\r\n\033[31m[ZTTP Policy]\033[0m Command '" + extractBinaryName(cmd) +
		"' is not permitted by your access policy.\r\n"
}

// extractBinaryName strips the path prefix and arguments from a command line,
// returning only the base binary name.
// Examples:
//
//	"/usr/bin/tmux -s main"  → "tmux"
//	"nohup ./server &"       → "nohup"
//	"ls -la /tmp"            → "ls"
func extractBinaryName(cmdLine string) string {
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
