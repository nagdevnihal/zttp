// internal/rbac/commands_test.go
// Pure unit tests for command filtering — no DB, no external deps.
package rbac

import "testing"

// ── Multiplexer Block Tests (always-on regardless of whitelist) ───────────────

func TestIsCommandAllowed_BlocksTmux(t *testing.T) {
	if IsCommandAllowed("tmux", nil) {
		t.Error("tmux must always be blocked")
	}
}

func TestIsCommandAllowed_BlocksScreen(t *testing.T) {
	if IsCommandAllowed("screen -S mysession", nil) {
		t.Error("screen must always be blocked")
	}
}

func TestIsCommandAllowed_BlocksNohup(t *testing.T) {
	if IsCommandAllowed("nohup ./server.sh &", nil) {
		t.Error("nohup must always be blocked")
	}
}

func TestIsCommandAllowed_BlocksFullPathTmux(t *testing.T) {
	if IsCommandAllowed("/usr/bin/tmux new-session", nil) {
		t.Error("/usr/bin/tmux must be blocked (path stripping)")
	}
}

func TestIsCommandAllowed_BlocksDisown(t *testing.T) {
	if IsCommandAllowed("disown %1", nil) {
		t.Error("disown must always be blocked")
	}
}

func TestIsCommandAllowed_BlocksSetsid(t *testing.T) {
	if IsCommandAllowed("setsid bash", nil) {
		t.Error("setsid must always be blocked")
	}
}

// Multiplexers must be blocked even when explicitly in the whitelist
func TestIsCommandAllowed_MultiplexerBlockedEvenIfWhitelisted(t *testing.T) {
	whitelist := []string{"tmux", "screen", "ls", "cat"}
	if IsCommandAllowed("tmux", whitelist) {
		t.Error("tmux must be blocked even when explicitly in whitelist")
	}
}

// ── Full Shell Tests (allowedCmds = nil) ─────────────────────────────────────

func TestIsCommandAllowed_FullShellAllowsLS(t *testing.T) {
	if !IsCommandAllowed("ls -la /tmp", nil) {
		t.Error("ls should be allowed when no command whitelist is set")
	}
}

func TestIsCommandAllowed_FullShellAllowsVim(t *testing.T) {
	if !IsCommandAllowed("vim /etc/config", nil) {
		t.Error("vim should be allowed in full shell mode")
	}
}

func TestIsCommandAllowed_FullShellAllowsEmptyLine(t *testing.T) {
	if !IsCommandAllowed("", nil) {
		t.Error("empty command should be allowed")
	}
}

func TestIsCommandAllowed_FullShellAllowsComplexCommand(t *testing.T) {
	if !IsCommandAllowed("grep -r 'error' /var/log/", nil) {
		t.Error("grep should be allowed in full shell mode")
	}
}

// ── Whitelist Enforcement Tests (allowedCmds = non-nil) ──────────────────────

func TestIsCommandAllowed_WhitelistAllowsListed(t *testing.T) {
	whitelist := []string{"ls", "cat", "grep", "tail"}
	if !IsCommandAllowed("ls -la", whitelist) {
		t.Error("ls should be permitted when in whitelist")
	}
	if !IsCommandAllowed("grep -i error /var/log/app.log", whitelist) {
		t.Error("grep should be permitted when in whitelist")
	}
}

func TestIsCommandAllowed_WhitelistBlocksUnlisted(t *testing.T) {
	whitelist := []string{"ls", "cat", "grep"}
	if IsCommandAllowed("rm -rf /tmp/test", whitelist) {
		t.Error("rm should be blocked when not in whitelist")
	}
	if IsCommandAllowed("vim /etc/hosts", whitelist) {
		t.Error("vim should be blocked when not in whitelist")
	}
}

func TestIsCommandAllowed_WhitelistCaseInsensitive(t *testing.T) {
	whitelist := []string{"LS", "CAT"}
	if !IsCommandAllowed("ls", whitelist) {
		t.Error("whitelist check should be case-insensitive")
	}
}

func TestIsCommandAllowed_WhitelistPathStripping(t *testing.T) {
	whitelist := []string{"cat"}
	if !IsCommandAllowed("/usr/bin/cat /etc/passwd", whitelist) {
		t.Error("full path binary should be stripped and matched against whitelist")
	}
}

// ── extractBinaryName Tests ───────────────────────────────────────────────────

func TestExtractBinaryName_SimpleName(t *testing.T) {
	if got := extractBinaryName("ls -la"); got != "ls" {
		t.Errorf("expected 'ls', got '%s'", got)
	}
}

func TestExtractBinaryName_FullPath(t *testing.T) {
	if got := extractBinaryName("/usr/bin/grep pattern file"); got != "grep" {
		t.Errorf("expected 'grep', got '%s'", got)
	}
}

func TestExtractBinaryName_EmptyString(t *testing.T) {
	if got := extractBinaryName(""); got != "" {
		t.Errorf("expected empty string, got '%s'", got)
	}
}

func TestExtractBinaryName_OnlySpaces(t *testing.T) {
	if got := extractBinaryName("   "); got != "" {
		t.Errorf("expected empty string for whitespace, got '%s'", got)
	}
}
