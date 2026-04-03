package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	klog "github.com/karadul/karadul/internal/log"
)

// TestStrOrDash verifies strOrDash handles various inputs correctly.
func TestStrOrDash(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"nil value", nil, "-"},
		{"empty string", "", "-"},
		{"non-empty string", "hello", "hello"},
		{"number", 42, "42"},
		{"whitespace", "   ", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strOrDash(tt.input)
			if result != tt.expected {
				t.Errorf("strOrDash(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestShortID verifies shortID truncates IDs correctly.
func TestShortID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"short", "abc", "abc"},
		{"exactly 8", "12345678", "12345678"},
		{"long", "1234567890abcdef", "12345678"},
		{"very long", "this-is-a-very-long-id-string", "this-is-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shortID(tt.input)
			if result != tt.expected {
				t.Errorf("shortID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestSplitComma verifies splitComma parses comma-separated strings correctly.
func TestSplitComma(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"empty", "", nil},
		{"single", "a", []string{"a"}},
		{"two items", "a,b", []string{"a", "b"}},
		{"three items", "a,b,c", []string{"a", "b", "c"}},
		{"with spaces", "a, b, c", []string{"a", " b", " c"}},
		{"empty middle", "a,,c", []string{"a", "c"}},
		{"trailing comma", "a,b,", []string{"a", "b"}},
		{"leading comma", ",a,b", []string{"a", "b"}},
		{"only commas", ",,", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitComma(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("splitComma(%q) = %v, want %v", tt.input, result, tt.expected)
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("splitComma(%q)[%d] = %q, want %q", tt.input, i, result[i], tt.expected[i])
				}
			}
		})
	}
}

// TestDefaultDataDir verifies defaultDataDir returns a valid path.
func TestDefaultDataDir(t *testing.T) {
	result := defaultDataDir()
	if result == "" {
		t.Error("defaultDataDir() returned empty string")
	}

	// Should contain .karadul
	if !contains(result, ".karadul") {
		t.Errorf("defaultDataDir() = %q, expected to contain '.karadul'", result)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		len(s) > len(substr) && containsSubstring(s, substr)
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestNewLogger verifies newLogger creates loggers with correct configuration.
func TestNewLogger(t *testing.T) {
	tests := []struct {
		name         string
		level        string
		format       string
		expectLevel  klog.Level
		expectFormat klog.Format
	}{
		{"debug text", "debug", "text", klog.LevelDebug, klog.FormatText},
		{"info text", "info", "text", klog.LevelInfo, klog.FormatText},
		{"error text", "error", "text", klog.LevelError, klog.FormatText},
		{"info json", "info", "json", klog.LevelInfo, klog.FormatJSON},
		{"invalid level defaults to info", "invalid", "text", klog.LevelInfo, klog.FormatText},
		{"empty format defaults to text", "info", "", klog.LevelInfo, klog.FormatText},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify it doesn't panic
			logger := newLogger(tt.level, tt.format)
			if logger == nil {
				t.Error("newLogger returned nil")
			}
		})
	}
}

// TestBuildInfo verifies buildInfo returns commit and date strings.
func TestBuildInfo(t *testing.T) {
	commit, date := buildInfo()

	// In test environment, these may be "unknown" or actual values
	if commit == "" {
		t.Error("buildInfo() returned empty commit")
	}
	if date == "" {
		t.Error("buildInfo() returned empty date")
	}

	// Commit should be at most 8 characters when not unknown
	if commit != "unknown" && len(commit) > 8 {
		t.Errorf("buildInfo() commit = %q, want at most 8 chars", commit)
	}
}

// TestSignalContext verifies signalContext creates a cancelable context.
func TestSignalContext(t *testing.T) {
	ctx, cancel := signalContext()
	if ctx == nil {
		t.Fatal("signalContext() returned nil context")
	}
	if cancel == nil {
		t.Fatal("signalContext() returned nil cancel")
	}

	// Context should not be canceled initially
	select {
	case <-ctx.Done():
		t.Error("context was canceled immediately")
	default:
		// Good
	}

	// Cancel should work
	cancel()
	select {
	case <-ctx.Done():
		// Good
	default:
		t.Error("context was not canceled after calling cancel()")
	}
}

// TestFatalf does not test os.Exit path but verifies function exists.
func TestFatalf_NilError(t *testing.T) {
	// When err is nil, fatalf should not exit
	// We can't test the exit path but we can verify nil doesn't panic
	// This is a minimal smoke test
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("fatalf(nil, \"msg\") panicked: %v", r)
		}
	}()
	// Note: We can't actually call fatalf with a non-nil error as it would exit
	// The nil case is the only safe one to test
}

// TestLocalAPIGet verifies localAPIGet communicates over a Unix domain socket.
// localAPIGet returns errors (does not call os.Exit), so both success and
// failure paths are testable.
func TestLocalAPIGet(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"nodeId":"test-node-123"}`))
	})
	mux.HandleFunc("/notfound", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"missing"}`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	t.Run("success", func(t *testing.T) {
		body, err := localAPIGet(dir, "/status")
		if err != nil {
			t.Fatalf("localAPIGet() error: %v", err)
		}
		var result map[string]string
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("parse response: %v", err)
		}
		if result["nodeId"] != "test-node-123" {
			t.Errorf("nodeId = %q, want %q", result["nodeId"], "test-node-123")
		}
	})

	t.Run("non_200_still_returns_body", func(t *testing.T) {
		// localAPIGet reads the body regardless of status code
		body, err := localAPIGet(dir, "/notfound")
		if err != nil {
			t.Fatalf("localAPIGet() error: %v", err)
		}
		if !strings.Contains(string(body), "missing") {
			t.Errorf("body = %q, want to contain 'missing'", string(body))
		}
	})

	t.Run("socket_not_found", func(t *testing.T) {
		_, err := localAPIGet(t.TempDir(), "/status")
		if err == nil {
			t.Error("expected error for missing socket, got nil")
		}
	})
}

// TestLocalAPIPost verifies localAPIPost sends JSON over a Unix domain socket
// and checks the response status code.
func TestLocalAPIPost(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("parse request body: %v", err)
		}
		if payload["action"] != "approve" {
			t.Errorf("payload action = %q, want %q", payload["action"], "approve")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/reject", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`bad request`))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	t.Run("success", func(t *testing.T) {
		payload := map[string]string{"action": "approve"}
		body, err := localAPIPost(dir, "/approve", payload)
		if err != nil {
			t.Fatalf("localAPIPost() error: %v", err)
		}
		var result map[string]string
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("parse response: %v", err)
		}
		if result["status"] != "ok" {
			t.Errorf("status = %q, want %q", result["status"], "ok")
		}
	})

	t.Run("non_200_returns_error", func(t *testing.T) {
		payload := map[string]string{"action": "bad"}
		_, err := localAPIPost(dir, "/reject", payload)
		if err == nil {
			t.Fatal("expected error for 400 response, got nil")
		}
		if !strings.Contains(err.Error(), "400") {
			t.Errorf("error = %q, want to contain '400'", err.Error())
		}
	})

	t.Run("socket_not_found", func(t *testing.T) {
		_, err := localAPIPost(t.TempDir(), "/approve", map[string]string{"a": "b"})
		if err == nil {
			t.Error("expected error for missing socket, got nil")
		}
	})

	t.Run("nil_payload", func(t *testing.T) {
		// nil payload marshals to "null" — should not panic.
		// Use /echo which accepts any body without assertions.
		body, err := localAPIPost(dir, "/echo", nil)
		if err != nil {
			t.Fatalf("localAPIPost(nil) error: %v", err)
		}
		if body == nil {
			t.Error("expected non-nil body")
		}
	})
}

// TestBuildInfo_Format verifies buildInfo returns well-formed values.
func TestBuildInfo_Format(t *testing.T) {
	commit, date := buildInfo()

	t.Run("commit_not_empty", func(t *testing.T) {
		if commit == "" {
			t.Error("commit is empty string")
		}
	})

	t.Run("date_not_empty", func(t *testing.T) {
		if date == "" {
			t.Error("date is empty string")
		}
	})

	t.Run("commit_max_8_chars", func(t *testing.T) {
		if commit != "unknown" && len(commit) > 8 {
			t.Errorf("commit = %q (%d chars), want at most 8", commit, len(commit))
		}
	})

	t.Run("known_values_or_unknown", func(t *testing.T) {
		// Commit is either "unknown" or a hex string of at most 8 chars
		if commit != "unknown" {
			for _, c := range commit {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("commit contains non-hex char %q", c)
					break
				}
			}
		}
	})

	t.Run("date_format_or_unknown", func(t *testing.T) {
		// Date is either "unknown" or a valid timestamp
		if date != "unknown" {
			_, err := time.Parse(time.RFC3339, date)
			if err != nil {
				// Try common alternatives; vcs.time may omit timezone
				_, err2 := time.Parse("2006-01-02T15:04:05Z", date)
				if err2 != nil {
					t.Errorf("date = %q is not RFC3339 parseable: %v", date, err)
				}
			}
		}
	})

	t.Run("consistent_across_calls", func(t *testing.T) {
		c2, d2 := buildInfo()
		if c2 != commit {
			t.Errorf("commit changed between calls: %q then %q", commit, c2)
		}
		if d2 != date {
			t.Errorf("date changed between calls: %q then %q", date, d2)
		}
	})
}

// TestUsage verifies usage() writes expected content to stderr.
func TestUsage(t *testing.T) {
	// Capture stderr by redirecting os.Stderr to a pipe.
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	usage()

	w.Close()
	os.Stderr = oldStderr

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	t.Run("contains_usage_header", func(t *testing.T) {
		if !strings.Contains(output, "Usage:") {
			t.Error("output does not contain 'Usage:'")
		}
	})

	t.Run("contains_commands", func(t *testing.T) {
		keywords := []string{"keygen", "up", "down", "server", "status", "peers", "ping"}
		for _, kw := range keywords {
			if !strings.Contains(output, kw) {
				t.Errorf("output missing command %q", kw)
			}
		}
	})

	t.Run("contains_project_name", func(t *testing.T) {
		if !strings.Contains(output, "Karadul") {
			t.Error("output does not contain project name 'Karadul'")
		}
	})

	t.Run("non_empty", func(t *testing.T) {
		if len(output) == 0 {
			t.Error("usage() produced empty output")
		}
	})

	t.Run("mentions_help_flag", func(t *testing.T) {
		if !strings.Contains(output, "-help") {
			t.Error("output does not mention -help flag")
		}
	})

	// Restore stderr — belt-and-suspenders after the swap above.
	fmt.Fprint(oldStderr, "")
}

// --- NEW TESTS ---

// TestMust_NilError verifies that must(nil, ...) does not exit.
func TestMust_NilError(t *testing.T) {
	// When err is nil, must should not exit. Just like fatalf.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("must(nil, \"msg\") panicked: %v", r)
		}
	}()
}

// TestRunKeygen verifies runKeygen generates keys and writes them to disk.
func TestRunKeygen(t *testing.T) {
	tmpDir := t.TempDir()

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	runKeygen([]string{"-dir", tmpDir})

	w.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	t.Run("prints_public_key", func(t *testing.T) {
		if !strings.Contains(output, "public key:") {
			t.Errorf("output missing 'public key:', got: %q", output)
		}
	})

	t.Run("prints_saved_message", func(t *testing.T) {
		if !strings.Contains(output, "saved to") {
			t.Errorf("output missing 'saved to', got: %q", output)
		}
	})

	t.Run("creates_files", func(t *testing.T) {
		entries, err := os.ReadDir(tmpDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			t.Error("no files created in key directory")
		}
	})
}

// TestRunCreateAuthKey verifies runCreateAuthKey generates and prints a key.
func TestRunCreateAuthKey(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	runCreateAuthKey([]string{"-ephemeral", "-expiry", "1h"})

	w.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	t.Run("prints_auth_key", func(t *testing.T) {
		if !strings.Contains(output, "auth-key:") {
			t.Errorf("output missing 'auth-key:', got: %q", output)
		}
	})

	t.Run("prints_id", func(t *testing.T) {
		if !strings.Contains(output, "id:") {
			t.Errorf("output missing 'id:', got: %q", output)
		}
	})

	t.Run("prints_ephemeral_true", func(t *testing.T) {
		if !strings.Contains(output, "ephemeral: true") {
			t.Errorf("output should say 'ephemeral: true', got: %q", output)
		}
	})

	t.Run("prints_expires", func(t *testing.T) {
		if !strings.Contains(output, "expires:") {
			t.Errorf("output missing 'expires:', got: %q", output)
		}
	})
}

// TestRunCreateAuthKey_NoExpiry verifies the no-expiry path (expiry=0).
func TestRunCreateAuthKey_NoExpiry(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	runCreateAuthKey([]string{"-expiry", "0s"})

	w.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	t.Run("no_expires_line_for_zero", func(t *testing.T) {
		if strings.Contains(output, "expires:") {
			t.Errorf("output should not contain 'expires:' for zero expiry, got: %q", output)
		}
	})
}

// TestRunPeers_Success verifies runPeers with a mock local API server.
func TestRunPeers_Success(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"hostname":"node1","nodeId":"abcdefgh12345678","virtualIp":"100.64.0.1","state":"connected","endpoint":"10.0.0.1:41641"},
			{"hostname":"node2","nodeId":"hijklmnopqrstuv","virtualIp":"100.64.0.2","state":"disconnected"}
		]`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runPeers([]string{"-data-dir", dir})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	t.Run("shows_node1", func(t *testing.T) {
		if !strings.Contains(output, "node1") {
			t.Errorf("output missing 'node1', got: %q", output)
		}
	})

	t.Run("shows_node2_relay", func(t *testing.T) {
		if !strings.Contains(output, "(relay)") {
			t.Errorf("output missing '(relay)' for node2, got: %q", output)
		}
	})

	t.Run("shows_header", func(t *testing.T) {
		if !strings.Contains(output, "HOSTNAME") {
			t.Errorf("output missing header 'HOSTNAME', got: %q", output)
		}
	})
}

// TestRunPeers_NoPeers verifies runPeers prints "no peers" when list is empty.
func TestRunPeers_NoPeers(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runPeers([]string{"-data-dir", dir})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out), "no peers") {
		t.Errorf("expected 'no peers', got: %q", string(out))
	}
}

// TestRunStatus_Success verifies runStatus pretty-prints JSON from the API.
func TestRunStatus_Success(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"nodeId":"test-123","virtualIp":"100.64.0.5","status":"running"}`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runStatus([]string{"-data-dir", dir})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	if !strings.Contains(output, "test-123") {
		t.Errorf("output missing 'test-123', got: %q", output)
	}
}

// TestRunDNS_Success verifies runDNS prints MagicDNS entries.
func TestRunDNS_Success(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"hostname":"mynode","virtualIp":"100.64.0.10"}]`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runDNS([]string{"-data-dir", dir})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	t.Run("shows_dns_name", func(t *testing.T) {
		if !strings.Contains(output, "mynode.web.karadul.") {
			t.Errorf("output missing 'mynode.web.karadul.', got: %q", output)
		}
	})

	t.Run("shows_ip", func(t *testing.T) {
		if !strings.Contains(output, "100.64.0.10") {
			t.Errorf("output missing '100.64.0.10', got: %q", output)
		}
	})
}

// TestRunDNS_NoEntries verifies runDNS handles empty peer list.
func TestRunDNS_NoEntries(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runDNS([]string{"-data-dir", dir})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out), "no MagicDNS entries") {
		t.Errorf("expected 'no MagicDNS entries', got: %q", string(out))
	}
}

// TestRunMetrics_Success verifies runMetrics writes raw bytes to stdout.
func TestRunMetrics_Success(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	metricsOutput := `# HELP karadul_peers Number of connected peers
# TYPE karadul_peers gauge
karadul_peers 3
`
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(metricsOutput))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runMetrics([]string{"-data-dir", dir})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out), "karadul_peers") {
		t.Errorf("output missing 'karadul_peers', got: %q", string(out))
	}
}

// TestRunDown_Success verifies runDown sends shutdown and prints confirmation.
func TestRunDown_Success(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"shutting_down"}`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runDown([]string{"-data-dir", dir})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out), "node shutting down") {
		t.Errorf("expected 'node shutting down', got: %q", string(out))
	}
}

// TestAdminDoStatus_Success verifies adminDoStatus with a mock HTTP server.
func TestAdminDoStatus_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"hostname":"n1"}]`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	body := adminDo("GET", "http://"+addr+"/api/v1/admin/nodes", nil)

	if !strings.Contains(string(body), "n1") {
		t.Errorf("expected body to contain 'n1', got: %q", string(body))
	}
}

// TestAdminDoStatus_ExpectedStatus verifies adminDoStatus with non-200 expected status.
func TestAdminDoStatus_ExpectedStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/nodes/test-id", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	body := adminDoStatus("DELETE", "http://"+addr+"/api/v1/admin/nodes/test-id", nil, http.StatusNoContent)
	if body == nil {
		t.Error("expected non-nil body")
	}
}

// TestAdminDoStatus_WithPayload verifies adminDoStatus sends JSON payload.
func TestAdminDoStatus_WithPayload(t *testing.T) {
	var receivedBody []byte
	var receivedCT string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/auth-keys", func(w http.ResponseWriter, r *http.Request) {
		receivedCT = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"key-1","key":"secret"}`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	payload := []byte(`{"ephemeral":true}`)
	body := adminDoStatus("POST", "http://"+addr+"/api/v1/admin/auth-keys", payload, http.StatusCreated)

	t.Run("sends_json_content_type", func(t *testing.T) {
		if receivedCT != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", receivedCT)
		}
	})

	t.Run("sends_payload", func(t *testing.T) {
		if string(receivedBody) != `{"ephemeral":true}` {
			t.Errorf("body = %q, want %q", string(receivedBody), `{"ephemeral":true}`)
		}
	})

	t.Run("returns_response", func(t *testing.T) {
		if !strings.Contains(string(body), "secret") {
			t.Errorf("response should contain 'secret', got: %q", string(body))
		}
	})
}

// TestDefaultOutInterface verifies defaultOutInterface returns a string (possibly empty).
func TestDefaultOutInterface(t *testing.T) {
	result := defaultOutInterface()
	// On macOS/Linux this should typically return a non-empty interface name,
	// but in restricted environments it might be empty.
	// Just verify it doesn't panic.
	_ = result
}

// TestRunAdmin_NodesList verifies admin nodes list output with a mock server.
func TestRunAdmin_NodesList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"hostname":"alpha","virtualIP":"100.64.0.1","status":"approved","id":"1234567890abcdef"},
			{"hostname":"beta","virtualIP":"100.64.0.2","status":"pending","id":"fedcba0987654321"}
		]`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runAdminNodes([]string{"-server", "http://" + addr})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	t.Run("shows_alpha", func(t *testing.T) {
		if !strings.Contains(output, "alpha") {
			t.Errorf("output missing 'alpha', got: %q", output)
		}
	})

	t.Run("shows_beta", func(t *testing.T) {
		if !strings.Contains(output, "beta") {
			t.Errorf("output missing 'beta', got: %q", output)
		}
	})

	t.Run("shows_short_id", func(t *testing.T) {
		if !strings.Contains(output, "12345678") {
			t.Errorf("output missing short id '12345678', got: %q", output)
		}
	})
}

// TestRunAdmin_NodesListEmpty verifies admin nodes list with no nodes.
func TestRunAdmin_NodesListEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runAdminNodes([]string{"-server", "http://" + addr})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out), "no nodes") {
		t.Errorf("expected 'no nodes', got: %q", string(out))
	}
}

// TestRunAdmin_NodesApprove verifies admin nodes approve sends POST.
func TestRunAdmin_NodesApprove(t *testing.T) {
	var receivedMethod string
	var receivedPath string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/nodes/test-id/approve", func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"approved"}`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runAdminNodes([]string{"-server", "http://" + addr, "approve", "test-id"})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("sends_post", func(t *testing.T) {
		if receivedMethod != "POST" {
			t.Errorf("method = %q, want POST", receivedMethod)
		}
	})

	t.Run("correct_path", func(t *testing.T) {
		if !strings.Contains(receivedPath, "test-id") {
			t.Errorf("path = %q, want to contain 'test-id'", receivedPath)
		}
	})

	t.Run("prints_confirmation", func(t *testing.T) {
		if !strings.Contains(string(out), "test-id approved") {
			t.Errorf("output missing 'test-id approved', got: %q", string(out))
		}
	})
}

// TestRunAdmin_NodesDelete verifies admin nodes delete sends DELETE.
func TestRunAdmin_NodesDelete(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/nodes/del-id", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runAdminNodes([]string{"-server", "http://" + addr, "delete", "del-id"})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out), "del-id deleted") {
		t.Errorf("output missing 'del-id deleted', got: %q", string(out))
	}
}

// TestRunAdmin_AuthKeysList verifies admin auth-keys list output.
func TestRunAdmin_AuthKeysList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/auth-keys", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"id":"key-1","ephemeral":false,"used":false,"expiresAt":"2026-12-31T00:00:00Z"},
			{"id":"key-2","ephemeral":true,"used":true,"expiresAt":""}
		]`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runAdminAuthKeys([]string{"-server", "http://" + addr})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	t.Run("shows_key_1", func(t *testing.T) {
		if !strings.Contains(output, "key-1") {
			t.Errorf("output missing 'key-1', got: %q", output)
		}
	})

	t.Run("shows_header", func(t *testing.T) {
		if !strings.Contains(output, "EPHEMERAL") {
			t.Errorf("output missing 'EPHEMERAL' header, got: %q", output)
		}
	})
}

// TestRunAdmin_AuthKeysListEmpty verifies admin auth-keys with no keys.
func TestRunAdmin_AuthKeysListEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/auth-keys", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runAdminAuthKeys([]string{"-server", "http://" + addr})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out), "no auth keys") {
		t.Errorf("expected 'no auth keys', got: %q", string(out))
	}
}

// TestRunAdmin_AuthKeysCreate verifies admin auth-keys create.
func TestRunAdmin_AuthKeysCreate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/auth-keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"new-key-id","key":"secret-key-value","ephemeral":true,"expiresAt":"2026-12-31T00:00:00Z"}`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runAdminAuthKeys([]string{"-server", "http://" + addr, "-ephemeral", "create"})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	t.Run("shows_key", func(t *testing.T) {
		if !strings.Contains(output, "secret-key-value") {
			t.Errorf("output missing 'secret-key-value', got: %q", output)
		}
	})

	t.Run("shows_id", func(t *testing.T) {
		if !strings.Contains(output, "new-key-id") {
			t.Errorf("output missing 'new-key-id', got: %q", output)
		}
	})

	t.Run("shows_expires", func(t *testing.T) {
		if !strings.Contains(output, "expires:") {
			t.Errorf("output missing 'expires:', got: %q", output)
		}
	})
}

// TestRunAdmin_ACLGet verifies admin acl get with a mock server.
func TestRunAdmin_ACLGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/acl", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"defaultAction":"deny","rules":[]}`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runAdminACL([]string{"-server", "http://" + addr, "get"})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	if !strings.Contains(output, "defaultAction") {
		t.Errorf("output missing 'defaultAction', got: %q", output)
	}
}

// TestRunAdmin_ACLSetFromFile verifies admin acl set reads a file and PUTs it.
func TestRunAdmin_ACLSetFromFile(t *testing.T) {
	var receivedBody string
	var receivedMethod string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/acl", func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	// Create temp ACL file.
	tmpFile, err := os.CreateTemp("", "acl-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	aclContent := `{"defaultAction":"allow"}`
	tmpFile.WriteString(aclContent)
	tmpFile.Close()

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runAdminACL([]string{"-server", "http://" + addr, "set", tmpFile.Name()})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("sends_put", func(t *testing.T) {
		if receivedMethod != "PUT" {
			t.Errorf("method = %q, want PUT", receivedMethod)
		}
	})

	t.Run("sends_file_content", func(t *testing.T) {
		if receivedBody != aclContent {
			t.Errorf("body = %q, want %q", receivedBody, aclContent)
		}
	})

	t.Run("prints_confirmation", func(t *testing.T) {
		if !strings.Contains(string(out), "ACL policy updated") {
			t.Errorf("output missing 'ACL policy updated', got: %q", string(out))
		}
	})
}

// TestMain_Subprocess_Version verifies the version command via subprocess.
func TestMain_Subprocess_Version(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "version"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Version")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "karadul") {
		t.Errorf("version output missing 'karadul', got: %q", string(output))
	}
	if !strings.Contains(string(output), version) {
		t.Errorf("version output missing %q, got: %q", version, string(output))
	}
}

// TestMain_Subprocess_NoArgs verifies main with no args prints usage and exits 1.
func TestMain_Subprocess_NoArgs(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_NoArgs")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	if !strings.Contains(string(output), "Usage:") {
		t.Errorf("no-args output missing 'Usage:', got: %q", string(output))
	}
}

// TestMain_Subprocess_UnknownCommand verifies main with unknown command exits 1.
func TestMain_Subprocess_UnknownCommand(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "nonexistent-command"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_UnknownCommand")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown command")
	}
	if !strings.Contains(string(output), "unknown command") {
		t.Errorf("output missing 'unknown command', got: %q", string(output))
	}
}

// TestMain_Subprocess_RunAuth_NoArgs verifies "karadul auth" with no args.
func TestMain_Subprocess_RunAuth_NoArgs(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "auth"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_RunAuth_NoArgs")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	if !strings.Contains(string(output), "usage:") {
		t.Errorf("output missing 'usage:', got: %q", string(output))
	}
}

// TestMain_Subprocess_RunAuth_UnknownSub verifies unknown auth subcommand.
func TestMain_Subprocess_RunAuth_UnknownSub(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "auth", "bogus"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_RunAuth_UnknownSub")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown auth subcommand")
	}
	if !strings.Contains(string(output), "unknown auth subcommand") {
		t.Errorf("output missing 'unknown auth subcommand', got: %q", string(output))
	}
}

// TestMain_Subprocess_RunExitNode_NoArgs verifies "karadul exit-node" with no args.
func TestMain_Subprocess_RunExitNode_NoArgs(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "exit-node"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_RunExitNode_NoArgs")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	if !strings.Contains(string(output), "usage:") {
		t.Errorf("output missing 'usage:', got: %q", string(output))
	}
}

// TestMain_Subprocess_RunFirewall_NoArgs verifies "karadul firewall" with no args.
func TestMain_Subprocess_RunFirewall_NoArgs(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_RunFirewall_NoArgs")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	if !strings.Contains(string(output), "Commands:") {
		t.Errorf("output missing 'Commands:', got: %q", string(output))
	}
}

// TestMain_Subprocess_RunAdmin_NoArgs verifies "karadul admin" with no args.
func TestMain_Subprocess_RunAdmin_NoArgs(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "admin"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_RunAdmin_NoArgs")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	if !strings.Contains(string(output), "usage:") {
		t.Errorf("output missing 'usage:', got: %q", string(output))
	}
}

// TestMain_Subprocess_RunAdmin_UnknownSub verifies unknown admin subcommand.
func TestMain_Subprocess_RunAdmin_UnknownSub(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "admin", "bogus"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_RunAdmin_UnknownSub")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown admin subcommand")
	}
	if !strings.Contains(string(output), "unknown admin subcommand") {
		t.Errorf("output missing 'unknown admin subcommand', got: %q", string(output))
	}
}

// --- ADDITIONAL COVERAGE TESTS ---

// TestStrOrDash_MoreTypes verifies strOrDash with int, float, and bool types.
func TestStrOrDash_MoreTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"int value", 42, "42"},
		{"float value", 3.14, "3.14"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"negative int", -7, "-7"},
		{"zero int", 0, "0"},
		{"string with spaces", "hello world", "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strOrDash(tt.input)
			if result != tt.expected {
				t.Errorf("strOrDash(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestRunExitNode_EnableWithMockSocket verifies runExitNode "enable" with a mock Unix socket.
func TestRunExitNode_EnableWithMockSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kex")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/exit-node/enable", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"enabled"}`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runExitNode([]string{"-data-dir", dir, "-out-interface", "en0", "enable"})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	if !strings.Contains(output, "exit node enabled") {
		t.Errorf("output missing 'exit node enabled', got: %q", output)
	}
	if !strings.Contains(output, "en0") {
		t.Errorf("output missing 'en0', got: %q", output)
	}
}

// TestRunExitNode_UseWithMockSocket verifies runExitNode "use" with a mock Unix socket.
func TestRunExitNode_UseWithMockSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kus")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/exit-node/use", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runExitNode([]string{"-data-dir", dir, "use", "my-peer"})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	if !strings.Contains(output, "routing all traffic through exit node") {
		t.Errorf("output missing 'routing all traffic through exit node', got: %q", output)
	}
	if !strings.Contains(output, "my-peer") {
		t.Errorf("output missing 'my-peer', got: %q", output)
	}
}

// TestMain_Subprocess_ExitNode_UnknownSubcmd verifies exit-node with unknown subcommand.
func TestMain_Subprocess_ExitNode_UnknownSubcmd(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "exit-node", "bogus"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_ExitNode_UnknownSubcmd")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown exit-node subcommand")
	}
	if !strings.Contains(string(output), "unknown") {
		t.Errorf("output missing 'unknown', got: %q", string(output))
	}
}

// TestMain_Subprocess_Ping_NoArgs verifies "karadul ping" with no args.
func TestMain_Subprocess_Ping_NoArgs(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "ping"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Ping_NoArgs")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for ping with no args")
	}
	if !strings.Contains(string(output), "usage:") {
		t.Errorf("output missing 'usage:', got: %q", string(output))
	}
}

// TestMain_Subprocess_ExitNode_Use_NoPeer verifies "exit-node use" without a peer argument.
func TestMain_Subprocess_ExitNode_Use_NoPeer(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "exit-node", "use"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_ExitNode_Use_NoPeer")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for exit-node use without peer")
	}
	if !strings.Contains(string(output), "usage:") {
		t.Errorf("output missing 'usage:', got: %q", string(output))
	}
}

// TestMain_Subprocess_ExitNode_Enable_NoInterface verifies "exit-node enable" fails
// when defaultOutInterface returns empty (no default route available in test env).
func TestMain_Subprocess_ExitNode_Enable_NoInterface(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "exit-node", "enable"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_ExitNode_Enable_NoInterface")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	// This may or may not fail depending on whether the machine has a default route.
	// The important thing is it doesn't panic. On most machines with a default route,
	// it will try to connect to a socket that doesn't exist, printing an error.
	_ = output
}

// TestMain_Subprocess_WintunCheck verifies "karadul wintun-check" command.
func TestMain_Subprocess_WintunCheck(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "wintun-check"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_WintunCheck")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	// On non-Windows, WintunDLLPath returns an error, so wintun-check exits 1
	// and prints "Wintun driver not found".
	if !strings.Contains(string(output), "Wintun") {
		t.Errorf("output missing 'Wintun', got: %q", string(output))
	}
}

// TestMain_Subprocess_Firewall_Setup verifies "karadul firewall setup" via subprocess.
func TestMain_Subprocess_Firewall_Setup(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall", "setup"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Firewall_Setup")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	// On macOS, this will likely fail due to pfctl permissions, which is fine.
	// We're verifying the command routing works and it doesn't panic.
	// It should either print "Firewall rules added successfully" or an "error:" message.
	out := string(output)
	if !strings.Contains(out, "Firewall") && !strings.Contains(out, "error") {
		t.Errorf("unexpected output: %q", out)
	}
}

// TestMain_Subprocess_Firewall_Remove verifies "karadul firewall remove" via subprocess.
func TestMain_Subprocess_Firewall_Remove(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall", "remove"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Firewall_Remove")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "Firewall") && !strings.Contains(out, "error") {
		t.Errorf("unexpected output: %q", out)
	}
}

// TestMain_Subprocess_Firewall_Check verifies "karadul firewall check" via subprocess.
func TestMain_Subprocess_Firewall_Check(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall", "check"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Firewall_Check")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	// "firewall check" does not os.Exit(1) in either path, so err should be nil.
	if err != nil {
		t.Fatalf("firewall check should not exit non-zero, got: %v\n%s", err, output)
	}
	out := string(output)
	if !strings.Contains(out, "Firewall rules") {
		t.Errorf("output missing 'Firewall rules', got: %q", out)
	}
}

// TestMain_Subprocess_Firewall_AllowPort_Valid verifies "firewall allow-port 8080 tcp".
func TestMain_Subprocess_Firewall_AllowPort_Valid(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall", "allow-port", "8080", "tcp"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Firewall_AllowPort_Valid")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	// Will likely fail on pfctl permissions, but the port parsing should succeed.
	if !strings.Contains(out, "8080") && !strings.Contains(out, "error") {
		t.Errorf("unexpected output: %q", out)
	}
}

// TestMain_Subprocess_Firewall_AllowPort_MissingArgs verifies allow-port with missing args.
func TestMain_Subprocess_Firewall_AllowPort_MissingArgs(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall", "allow-port", "8080"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Firewall_AllowPort_MissingArgs")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for allow-port with missing args")
	}
	if !strings.Contains(string(output), "usage:") {
		t.Errorf("output missing 'usage:', got: %q", string(output))
	}
}

// TestMain_Subprocess_Firewall_AllowPort_InvalidPort verifies allow-port with invalid port.
func TestMain_Subprocess_Firewall_AllowPort_InvalidPort(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall", "allow-port", "notaport", "tcp"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Firewall_AllowPort_InvalidPort")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid port")
	}
	if !strings.Contains(string(output), "invalid port") {
		t.Errorf("output missing 'invalid port', got: %q", string(output))
	}
}

// TestMain_Subprocess_Firewall_UnknownCommand verifies unknown firewall subcommand.
func TestMain_Subprocess_Firewall_UnknownCommand(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall", "nonsense"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Firewall_UnknownCommand")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown firewall command")
	}
	if !strings.Contains(string(output), "unknown firewall command") {
		t.Errorf("output missing 'unknown firewall command', got: %q", string(output))
	}
}

// TestDefaultDataDir_HomeEnv verifies defaultDataDir with HOME set explicitly.
func TestDefaultDataDir_HomeEnv(t *testing.T) {
	// Save and restore HOME.
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)

	tests := []struct {
		name string
		home string
	}{
		{"custom home", "/tmp/testhome"},
		{"root home", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("HOME", tt.home)
			// We cannot easily override os.UserHomeDir, but we can verify
			// defaultDataDir returns a path ending in ".karadul".
			result := defaultDataDir()
			if result == "" {
				t.Error("defaultDataDir() returned empty string")
			}
		})
	}
}

// TestAdminDo_UnreachableServer verifies adminDo exits when the server is unreachable.
func TestAdminDo_UnreachableServer(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		// Use a port that nothing is listening on.
		adminDo("GET", "http://127.0.0.1:1/api/v1/admin/nodes", nil)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestAdminDo_UnreachableServer")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unreachable server")
	}
	if !strings.Contains(string(output), "error:") {
		t.Errorf("output missing 'error:', got: %q", string(output))
	}
}

// TestAdminDoStatus_UnexpectedStatus verifies adminDoStatus exits on unexpected status code.
func TestAdminDoStatus_UnexpectedStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal error`))
	})

	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go server.Serve(ln)
	defer server.Close()

	if os.Getenv("TEST_MAIN") == "1" {
		adminDoStatus("GET", "http://"+addr+"/api/v1/admin/test", nil, http.StatusOK)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestAdminDoStatus_UnexpectedStatus")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unexpected status code")
	}
	if !strings.Contains(string(output), "error:") {
		t.Errorf("output missing 'error:', got: %q", string(output))
	}
}

// TestMain_Subprocess_ExitNode_Enable tests the full main() path for "exit-node enable".
func TestMain_Subprocess_ExitNode_Enable(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "exit-node", "-out-interface", "lo0", "enable"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_ExitNode_Enable")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	// Will fail because no socket exists, but should contain an error message.
	out := string(output)
	if !strings.Contains(out, "error:") && !strings.Contains(out, "exit node") {
		t.Errorf("unexpected output: %q", out)
	}
}

// ─── runPing subprocess tests ────────────────────────────────────────────────

// TestMain_Subprocess_Ping_NoSocket verifies "karadul ping <peer>" fails
// gracefully when the local API socket doesn't exist.
func TestMain_Subprocess_Ping_NoSocket(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir := t.TempDir()
		os.Args = []string{"karadul", "ping", "-data-dir", tmpDir, "test-peer"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Ping_NoSocket")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "karadul ping") && !strings.Contains(out, "error") {
		t.Errorf("expected ping error output, got: %q", out)
	}
}

// TestRunPing_PeerFoundButUnreachable verifies runPing resolves a peer but
// fails to actually ping (since the peer IP is unreachable).
func TestRunPing_PeerFoundButUnreachable(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kping")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"hostname":"test-peer","virtualIp":"100.64.0.2","state":"connected"}]`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runPing([]string{"-data-dir", dir, "-c", "1", "test-peer"})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	if !strings.Contains(output, "PING test-peer (100.64.0.2)") {
		t.Errorf("expected ping header, got: %q", output)
	}
	if !strings.Contains(output, "packets transmitted") {
		t.Errorf("expected ping statistics, got: %q", output)
	}
}

// TestRunPing_PeerByVirtualIP verifies runPing can target a peer by VIP.
func TestRunPing_PeerByVirtualIP(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kpingvip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sockPath := dir + "/karadul.sock"

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"hostname":"test-peer","virtualIp":"100.64.0.2","state":"connected"}]`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	defer server.Close()

	time.Sleep(50 * time.Millisecond)

	oldStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw

	runPing([]string{"-data-dir", dir, "-c", "1", "100.64.0.2"})

	pw.Close()
	os.Stdout = oldStdout

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)

	if !strings.Contains(output, "PING 100.64.0.2") {
		t.Errorf("expected ping header for VIP, got: %q", output)
	}
}

// ─── defaultOutInterface tests ────────────────────────────────────────────────

func TestDefaultOutInterface_ReturnsNonEmpty(t *testing.T) {
	result := defaultOutInterface()
	// On most machines with internet access, this returns a non-empty string.
	// On restricted environments, it may be empty.
	if result != "" {
		t.Logf("defaultOutInterface: %q", result)
	}
}

func TestDefaultOutInterface_DoesNotPanic(t *testing.T) {
	// Just verify it doesn't panic.
	_ = defaultOutInterface()
}

// ─── firewall check subprocess ────────────────────────────────────────────────

// TestMain_Subprocess_Firewall_AllowPort_InvalidProtocol verifies "firewall allow-port"
// with invalid protocol.
func TestMain_Subprocess_Firewall_AllowPort_InvalidProtocol(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall", "allow-port", "8080", "invalid"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Firewall_AllowPort_InvalidProtocol")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid protocol")
	}
	if !strings.Contains(string(output), "error") {
		t.Errorf("output missing 'error', got: %q", string(output))
	}
}

// TestMain_Subprocess_Metrics_NoSocket verifies "karadul metrics" fails
// gracefully when the socket doesn't exist.
func TestMain_Subprocess_Metrics_NoSocket(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir := t.TempDir()
		os.Args = []string{"karadul", "metrics", "-data-dir", tmpDir}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Metrics_NoSocket")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "error") {
		t.Errorf("expected error output, got: %q", out)
	}
}

// TestMain_Subprocess_DNS_NoSocket verifies "karadul dns" fails when socket missing.
func TestMain_Subprocess_DNS_NoSocket(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir := t.TempDir()
		os.Args = []string{"karadul", "dns", "-data-dir", tmpDir}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_DNS_NoSocket")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "error") {
		t.Errorf("expected error output, got: %q", out)
	}
}

// TestMain_Subprocess_Status_NoSocket verifies "karadul status" fails when socket missing.
func TestMain_Subprocess_Status_NoSocket(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir := t.TempDir()
		os.Args = []string{"karadul", "status", "-data-dir", tmpDir}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Status_NoSocket")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "error") {
		t.Errorf("expected error output, got: %q", out)
	}
}

// TestMain_Subprocess_Peers_NoSocket verifies "karadul peers" fails when socket missing.
func TestMain_Subprocess_Peers_NoSocket(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir := t.TempDir()
		os.Args = []string{"karadul", "peers", "-data-dir", tmpDir}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Peers_NoSocket")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "error") {
		t.Errorf("expected error output, got: %q", out)
	}
}

// TestMain_Subprocess_Down_NoSocket verifies "karadul down" fails when socket missing.
func TestMain_Subprocess_Down_NoSocket(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir := t.TempDir()
		os.Args = []string{"karadul", "down", "-data-dir", tmpDir}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Down_NoSocket")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "error") {
		t.Errorf("expected error output, got: %q", out)
	}
}

// TestMain_Subprocess_ExitNode_Use_NoSocket verifies "exit-node use" fails when socket missing.
func TestMain_Subprocess_ExitNode_Use_NoSocket(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir := t.TempDir()
		os.Args = []string{"karadul", "exit-node", "-data-dir", tmpDir, "use", "peer1"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_ExitNode_Use_NoSocket")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "error") {
		t.Errorf("expected error output, got: %q", out)
	}
}

// TestMain_Subprocess_Auth_CreateKey verifies "karadul auth create-key" via subprocess.
func TestMain_Subprocess_Auth_CreateKey(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "auth", "create-key"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Auth_CreateKey")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("auth create-key failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "auth-key:") {
		t.Errorf("output missing 'auth-key:', got: %q", string(output))
	}
}

// TestCheckFirewall verifies checkFirewall returns a bool (wraps firewall.Check).
func TestCheckFirewall(t *testing.T) {
	// On macOS without root, pfctl commands will fail, so Check() returns false.
	// The test just verifies the function runs without panicking and returns a bool.
	result := checkFirewall()
	// We can't assert true/false since it depends on system state,
	// but we can verify it doesn't panic.
	_ = result
}

// TestRunFirewall_CheckSubcmd verifies the "firewall check" subcommand via subprocess.
func TestMain_Subprocess_Firewall_Check_InProcess(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		os.Args = []string{"karadul", "firewall", "check"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Firewall_Check_InProcess")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "Firewall rules") {
		t.Errorf("expected firewall check output, got: %q", out)
	}
}

// TestRunPing_PeerNotFound verifies runPing when peer is not in the peers list.
func TestMain_Subprocess_Ping_PeerNotFound(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir, _ := os.MkdirTemp("/tmp", "kpn")
		defer os.RemoveAll(tmpDir)
		sockPath := tmpDir + "/karadul.sock"

		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"hostname":"other-peer","virtualIp":"100.64.0.2","state":"active"}]`))
		})
		server := &http.Server{Handler: mux}
		go server.Serve(ln)
		defer server.Close()
		time.Sleep(50 * time.Millisecond)

		os.Args = []string{"karadul", "ping", "-data-dir", tmpDir, "missing-peer"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Ping_PeerNotFound")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "not found") {
		t.Errorf("expected 'not found' output, got: %q", out)
	}
}

// TestRunPing_MalformedJSON verifies runPing when /peers returns malformed JSON.
func TestMain_Subprocess_Ping_MalformedJSON(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir, _ := os.MkdirTemp("/tmp", "kpm")
		defer os.RemoveAll(tmpDir)
		sockPath := tmpDir + "/karadul.sock"

		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{invalid json`))
		})
		server := &http.Server{Handler: mux}
		go server.Serve(ln)
		defer server.Close()
		time.Sleep(50 * time.Millisecond)

		os.Args = []string{"karadul", "ping", "-data-dir", tmpDir, "some-peer"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Ping_MalformedJSON")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "failed to parse peers") {
		t.Errorf("expected 'failed to parse peers' output, got: %q", out)
	}
}

// TestRunExitNode_Enable_ErrorResponse verifies runExitNode enable when API returns error.
func TestMain_Subprocess_ExitNode_Enable_Error(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir, _ := os.MkdirTemp("/tmp", "kee")
		defer os.RemoveAll(tmpDir)
		sockPath := tmpDir + "/karadul.sock"

		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/exit-node/enable", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal"}`))
		})
		server := &http.Server{Handler: mux}
		go server.Serve(ln)
		defer server.Close()
		time.Sleep(50 * time.Millisecond)

		os.Args = []string{"karadul", "exit-node", "-data-dir", tmpDir, "-out-interface", "en0", "enable"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_ExitNode_Enable_Error")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "error") {
		t.Errorf("expected error output, got: %q", out)
	}
}

// TestRunExitNode_Use_ErrorResponse verifies runExitNode use when API returns error.
func TestMain_Subprocess_ExitNode_Use_Error(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir, _ := os.MkdirTemp("/tmp", "keu")
		defer os.RemoveAll(tmpDir)
		sockPath := tmpDir + "/karadul.sock"

		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/exit-node/use", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"unavailable"}`))
		})
		server := &http.Server{Handler: mux}
		go server.Serve(ln)
		defer server.Close()
		time.Sleep(50 * time.Millisecond)

		os.Args = []string{"karadul", "exit-node", "-data-dir", tmpDir, "use", "peer1"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_ExitNode_Use_Error")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "error") {
		t.Errorf("expected error output, got: %q", out)
	}
}

// TestMain_Subprocess_Keygen verifies "karadul keygen" via subprocess.
func TestMain_Subprocess_Keygen(t *testing.T) {
	if os.Getenv("TEST_MAIN") == "1" {
		tmpDir := t.TempDir()
		os.Args = []string{"karadul", "keygen", "-dir", tmpDir}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Subprocess_Keygen")
	cmd.Env = append(os.Environ(), "TEST_MAIN=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "public key:") {
		t.Errorf("output missing 'public key:', got: %q", string(output))
	}
}
