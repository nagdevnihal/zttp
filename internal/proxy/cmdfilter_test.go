// internal/proxy/cmdfilter_test.go
package proxy

import (
	"bytes"
	"strings"
	"testing"
)

func TestCommandFilterWriter_AllowsNormalCommands(t *testing.T) {
	var target, clientW bytes.Buffer
	fw := newCommandFilterWriter(&target, &clientW, nil)

	input := []byte("ls -la\ncat /etc/passwd\r\n")
	n, err := fw.Write(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(input) {
		t.Errorf("expected %d bytes written, got %d", len(input), n)
	}

	if target.String() != "ls -la\ncat /etc/passwd\r\n" {
		t.Errorf("target did not receive expected bytes, got: %q", target.String())
	}
	if clientW.Len() > 0 {
		t.Errorf("expected empty client writer, got: %q", clientW.String())
	}
}

func TestCommandFilterWriter_BlocksMultiplexer(t *testing.T) {
	var target, clientW bytes.Buffer
	fw := newCommandFilterWriter(&target, &clientW, nil)

	input := []byte("tmux new -s test\nls\n")
	_, err := fw.Write(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// target should only receive the 'ls\n'
	if target.String() != "ls\n" {
		t.Errorf("expected target to receive 'ls\\n', got: %q", target.String())
	}

	// clientW should receive the policy violation message
	if !strings.Contains(clientW.String(), "Command 'tmux' is prohibited") {
		t.Errorf("client did not receive proper violation message, got: %q", clientW.String())
	}
}

func TestCommandFilterWriter_EnforcesWhitelist(t *testing.T) {
	var target, clientW bytes.Buffer
	whitelist := []string{"cat", "grep"}
	fw := newCommandFilterWriter(&target, &clientW, whitelist)

	input := []byte("cat /tmp/test\nrm -rf /\n")
	_, err := fw.Write(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if target.String() != "cat /tmp/test\n" {
		t.Errorf("expected target to receive 'cat /tmp/test\\n', got: %q", target.String())
	}

	if !strings.Contains(clientW.String(), "not permitted by your access policy") {
		t.Errorf("client did not receive proper whitelist violation message, got: %q", clientW.String())
	}
}
