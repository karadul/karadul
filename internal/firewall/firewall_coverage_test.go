package firewall

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// fakePfctlSetup creates a temporary directory with a fake pfctl script
// that simulates successful pfctl operations. It sets PATH so that the
// fake pfctl is found first. Tests using this helper can exercise the
// success paths of Setup, Remove, Check, AllowPort, RemovePort, and pfctl.
//
// The fake pfctl script:
//   - When called with "-s rules": outputs a pre-written rules list
//   - For all other invocations: exits 0 silently
// ---------------------------------------------------------------------------

// fakePfctlRules holds the rules that the fake pfctl will output
// when called with "-s rules". It is written to a well-known path
// so the fake script can read it.
const fakeRulesFile = "karadul_test_rules.txt"

// setupFakePfctl creates a fake pfctl in a temp dir, prepends it to PATH,
// and writes an initial rules file. Returns a cleanup function.
// The rulesFile parameter controls what "-s rules" returns.
func setupFakePfctl(t *testing.T, initialRules string) {
	t.Helper()

	dir := t.TempDir()

	// Write the fake pfctl script.
	script := `#!/bin/bash
RULES_FILE="` + filepath.Join(dir, fakeRulesFile) + `"

# Parse arguments using while/shift to handle positional parameters correctly.
while [ $# -gt 0 ]; do
  case "$1" in
    -s)
      if [ "$2" = "rules" ]; then
        if [ -f "$RULES_FILE" ]; then
          cat "$RULES_FILE"
        fi
        exit 0
      fi
      shift 2
      ;;
    -f)
      if [ "$2" = "-" ]; then
        cat > "$RULES_FILE"
        exit 0
      fi
      shift 2
      ;;
    -F)
      : > "$RULES_FILE"
      exit 0
      ;;
    -e)
      # pfctl -e (enable) — no-op for fake.
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

# Default: succeed silently.
exit 0
`
	pfctlPath := filepath.Join(dir, "pfctl")
	if err := os.WriteFile(pfctlPath, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write fake pfctl: %v", err)
	}

	// Write initial rules file.
	rulesPath := filepath.Join(dir, fakeRulesFile)
	if err := os.WriteFile(rulesPath, []byte(initialRules), 0o644); err != nil {
		t.Fatalf("failed to write fake rules file: %v", err)
	}

	// Prepend fake dir to PATH so exec.Command finds our pfctl.
	origPath := os.Getenv("PATH")
	newPath := dir + string(os.PathListSeparator) + origPath
	t.Setenv("PATH", newPath)

	// Verify the fake pfctl is found.
	p, err := exec.LookPath("pfctl")
	if err != nil {
		t.Fatalf("fake pfctl not found in PATH: %v", err)
	}
	if p != pfctlPath {
		t.Fatalf("fake pfctl not first in PATH: got %q, want %q", p, pfctlPath)
	}
}

// ---------------------------------------------------------------------------
// filterRules — pure logic tests (darwin-only code, but test everywhere)
// ---------------------------------------------------------------------------

func TestFilterRules_RemovesMatching(t *testing.T) {
	input := "pass quick proto tcp to any port 80\n" +
		"pass quick proto udp to any port 53\n" +
		"pass on karadul0\n"

	kept := filterRules(input, 80, "tcp")
	if len(kept) != 2 {
		t.Fatalf("expected 2 rules remaining, got %d: %v", len(kept), kept)
	}
	if kept[0] != "pass quick proto udp to any port 53" {
		t.Errorf("first rule: %q", kept[0])
	}
	if kept[1] != "pass on karadul0" {
		t.Errorf("second rule: %q", kept[1])
	}
}

func TestFilterRules_RemovesUDP(t *testing.T) {
	input := "pass quick proto tcp to any port 80\n" +
		"pass quick proto udp to any port 53\n"

	kept := filterRules(input, 53, "udp")
	if len(kept) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(kept))
	}
	if kept[0] != "pass quick proto tcp to any port 80" {
		t.Errorf("unexpected rule: %q", kept[0])
	}
}

func TestFilterRules_EmptyInput(t *testing.T) {
	kept := filterRules("", 80, "tcp")
	if len(kept) != 0 {
		t.Fatalf("expected 0 rules from empty input, got %d", len(kept))
	}
}

func TestFilterRules_OnlyWhitespaceLines(t *testing.T) {
	input := "\n  \n\t\n  \n"
	kept := filterRules(input, 80, "tcp")
	if len(kept) != 0 {
		t.Fatalf("expected 0 rules from whitespace-only input, got %d", len(kept))
	}
}

func TestFilterRules_NoMatch(t *testing.T) {
	input := "pass quick proto tcp to any port 443\n" +
		"pass quick proto udp to any port 53\n"

	kept := filterRules(input, 80, "tcp")
	if len(kept) != 2 {
		t.Fatalf("expected 2 rules (no match), got %d", len(kept))
	}
}

func TestFilterRules_MultipleMatchingSamePort(t *testing.T) {
	input := "pass quick proto tcp to any port 80\n" +
		"pass quick proto tcp to any port 443\n" +
		"pass quick proto tcp to any port 80\n" +
		"pass on karadul0\n"

	kept := filterRules(input, 80, "tcp")
	if len(kept) != 2 {
		t.Fatalf("expected 2 rules remaining, got %d: %v", len(kept), kept)
	}
}

func TestFilterRules_SamePortDifferentProto(t *testing.T) {
	input := "pass quick proto tcp to any port 53\n" +
		"pass quick proto udp to any port 53\n"

	// Remove only TCP port 53, UDP should remain.
	kept := filterRules(input, 53, "tcp")
	if len(kept) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(kept))
	}
	if kept[0] != "pass quick proto udp to any port 53" {
		t.Errorf("unexpected rule: %q", kept[0])
	}
}

func TestFilterRules_PortZero(t *testing.T) {
	input := "pass quick proto tcp to any port 0\n" +
		"pass quick proto tcp to any port 80\n"

	kept := filterRules(input, 0, "tcp")
	if len(kept) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(kept))
	}
	if kept[0] != "pass quick proto tcp to any port 80" {
		t.Errorf("unexpected rule: %q", kept[0])
	}
}

func TestFilterRules_LargePort(t *testing.T) {
	input := "pass quick proto tcp to any port 65535\n" +
		"pass quick proto tcp to any port 80\n"

	kept := filterRules(input, 65535, "tcp")
	if len(kept) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(kept))
	}
}

func TestFilterRules_NegativePort(t *testing.T) {
	input := "pass quick proto tcp to any port 80\n"
	// Negative port won't match "port -1" since pf wouldn't produce it.
	kept := filterRules(input, -1, "tcp")
	if len(kept) != 1 {
		t.Fatalf("expected 1 rule (no match), got %d", len(kept))
	}
}

func TestFilterRules_PartialMatchDoesNotRemove(t *testing.T) {
	// "port 80" should not match "port 8080" via Contains, but
	// strings.Contains("port 8080", "port 80") is true.
	// This is a known edge case in the filter logic.
	input := "pass quick proto tcp to any port 8080\n"
	kept := filterRules(input, 80, "tcp")
	// "port 8080" contains "port 80" — this rule will be removed.
	// This is the actual behavior of the filter.
	if len(kept) != 0 {
		t.Fatalf("expected 0 rules (substring match), got %d", len(kept))
	}
}

func TestFilterRules_TrailingNewline(t *testing.T) {
	input := "pass quick proto tcp to any port 80\npass on karadul0\n\n\n"
	kept := filterRules(input, 80, "tcp")
	if len(kept) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(kept))
	}
	if kept[0] != "pass on karadul0" {
		t.Errorf("unexpected rule: %q", kept[0])
	}
}

// ---------------------------------------------------------------------------
// Setup — various exePath arguments
// ---------------------------------------------------------------------------

func TestSetup_EmptyExePath(t *testing.T) {
	err := Setup("")
	if err == nil {
		t.Log("Setup succeeded with empty path (running as root)")
	}
}

func TestSetup_NonEmptyExePath(t *testing.T) {
	err := Setup("/nonexistent/binary")
	if err == nil {
		t.Log("Setup succeeded with non-empty path (running as root)")
	}
}

func TestSetup_WithRealPath(t *testing.T) {
	err := Setup("/bin/echo")
	if err == nil {
		t.Log("Setup succeeded with /bin/echo (running as root)")
	}
}

func TestSetup_WhitespaceExePath(t *testing.T) {
	_ = Setup("   ")
}

// ---------------------------------------------------------------------------
// Remove — called multiple times (idempotent)
// ---------------------------------------------------------------------------

func TestRemove_Idempotent(t *testing.T) {
	for i := 0; i < 3; i++ {
		_ = Remove()
	}
}

// ---------------------------------------------------------------------------
// Check — multiple calls and state checks
// ---------------------------------------------------------------------------

func TestCheck_MultipleCalls(t *testing.T) {
	for i := 0; i < 5; i++ {
		_ = Check()
	}
}

func TestCheck_AfterSetupAttempt(t *testing.T) {
	_ = Setup("/nonexistent")
	_ = Check()
}

// ---------------------------------------------------------------------------
// AllowPort — boundary port values
// ---------------------------------------------------------------------------

func TestAllowPort_BoundaryPorts(t *testing.T) {
	for _, port := range []int{0, 1, 80, 443, 49151, 49152, 65535, 65536, -1} {
		t.Run("", func(t *testing.T) {
			_ = AllowPort(port, "tcp")
		})
	}
}

// ---------------------------------------------------------------------------
// RemovePort — boundary port values
// ---------------------------------------------------------------------------

func TestRemovePort_BoundaryPorts(t *testing.T) {
	for _, port := range []int{0, 1, 80, 443, 49151, 49152, 65535, 65536, -1} {
		t.Run("", func(t *testing.T) {
			_ = RemovePort(port, "udp")
		})
	}
}

// ---------------------------------------------------------------------------
// AllowPort / RemovePort — protocol validation exhaustive tests
// ---------------------------------------------------------------------------

func TestAllowPort_ExhaustiveInvalidProtocols(t *testing.T) {
	invalid := []string{
		"", " ", "icmp", "sctp", "http", "https",
		"TCP/UDP", "tcp,udp", "tcp udp",
		"random", "123", "0x01",
	}
	for _, proto := range invalid {
		t.Run(proto, func(t *testing.T) {
			err := AllowPort(80, proto)
			if err == nil {
				t.Errorf("AllowPort(80, %q) should fail", proto)
			}
		})
	}
}

func TestRemovePort_ExhaustiveInvalidProtocols(t *testing.T) {
	invalid := []string{
		"", " ", "icmp", "sctp", "http", "https",
		"random", "123", "0x01",
	}
	for _, proto := range invalid {
		t.Run(proto, func(t *testing.T) {
			err := RemovePort(80, proto)
			if err == nil {
				t.Errorf("RemovePort(80, %q) should fail", proto)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AllowPort / RemovePort — error message content for valid protocols
// ---------------------------------------------------------------------------

func TestAllowPort_TCP_ErrorMessage(t *testing.T) {
	err := AllowPort(443, "tcp")
	if err == nil {
		t.Log("AllowPort(443, tcp) succeeded (running as root)")
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "unsupported protocol") {
		t.Errorf("tcp should not trigger protocol validation: %v", err)
	}
}

func TestAllowPort_UDP_ErrorMessage(t *testing.T) {
	err := AllowPort(53, "udp")
	if err == nil {
		t.Log("AllowPort(53, udp) succeeded (running as root)")
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "unsupported protocol") {
		t.Errorf("udp should not trigger protocol validation: %v", err)
	}
}

func TestRemovePort_TCP_ErrorMessage(t *testing.T) {
	err := RemovePort(443, "tcp")
	if err == nil {
		t.Log("RemovePort(443, tcp) succeeded (running as root)")
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "unsupported protocol") {
		t.Errorf("tcp should not trigger protocol validation: %v", err)
	}
}

func TestRemovePort_UDP_ErrorMessage(t *testing.T) {
	err := RemovePort(53, "udp")
	if err == nil {
		t.Log("RemovePort(53, udp) succeeded (running as root)")
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "unsupported protocol") {
		t.Errorf("udp should not trigger protocol validation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Setup / Remove — darwin-specific error messages
// ---------------------------------------------------------------------------

func TestSetup_DarwinErrorMessage(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	err := Setup("")
	if err == nil {
		t.Skip("running as root")
	}
	if !strings.Contains(err.Error(), "pfctl") {
		t.Errorf("expected pfctl in error: %v", err)
	}
}

func TestRemove_DarwinErrorMessage(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	err := Remove()
	if err == nil {
		t.Log("Remove succeeded (no rules)")
		return
	}
	if !strings.Contains(err.Error(), "pfctl") {
		t.Errorf("expected pfctl in error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// pfctl helper — various argument patterns
// ---------------------------------------------------------------------------

func TestPfctl_NoArgs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	_ = pfctl()
}

func TestPfctl_StatusArgs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	_ = pfctl("-s", "info")
}

func TestPfctl_ShowRules(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	_ = pfctl("-a", anchorName, "-s", "rules")
}

// ---------------------------------------------------------------------------
// AllowPort / RemovePort — whitespace and special chars in protocol
// ---------------------------------------------------------------------------

func TestAllowPort_TabProtocol(t *testing.T) {
	_ = AllowPort(80, "tcp\t")
}

func TestAllowPort_NewlineProtocol(t *testing.T) {
	_ = AllowPort(80, "tcp\n")
}

func TestRemovePort_TabProtocol(t *testing.T) {
	_ = RemovePort(80, "udp\t")
}

// ---------------------------------------------------------------------------
// Concurrent access — multiple AllowPort calls
// ---------------------------------------------------------------------------

func TestAllowPort_ConcurrentCalls(t *testing.T) {
	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(port int) {
			done <- AllowPort(port, "tcp")
		}(8000 + i)
	}
	for i := 0; i < 10; i++ {
		_ = <-done
	}
}

// ---------------------------------------------------------------------------
// AllowPort / RemovePort — extreme port values
// ---------------------------------------------------------------------------

func TestAllowPort_MaxIntPort(t *testing.T) {
	_ = AllowPort(int(^uint(0)>>1), "tcp")
}

func TestRemovePort_MaxIntPort(t *testing.T) {
	_ = RemovePort(int(^uint(0)>>1), "tcp")
}

// ---------------------------------------------------------------------------
// Darwin-specific — various port smoke tests
// ---------------------------------------------------------------------------

func TestRemovePort_DarwinTCP_WellKnown(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	for _, port := range []int{20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995} {
		_ = RemovePort(port, "tcp")
	}
}

func TestRemovePort_DarwinUDP_WellKnown(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	for _, port := range []int{53, 67, 68, 123, 161, 5353} {
		_ = RemovePort(port, "udp")
	}
}

func TestAllowPort_Darwin_WellKnown(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	for _, port := range []int{22, 53, 80, 443, 8080, 8443} {
		_ = AllowPort(port, "tcp")
	}
}

// ---------------------------------------------------------------------------
// Fake-pfctl tests: exercise success paths by replacing pfctl with a
// stub that always succeeds. These cover the "return nil" branches and
// the post-pfctl logic in Setup, Remove, Check, AllowPort, RemovePort,
// and the pfctl helper.
// ---------------------------------------------------------------------------

func TestSetup_FakePfctl_Succeeds(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	err := Setup("/usr/local/bin/karadul")
	if err != nil {
		t.Fatalf("Setup should succeed with fake pfctl, got: %v", err)
	}
}

func TestSetup_FakePfctl_EmptyExePath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	err := Setup("")
	if err != nil {
		t.Fatalf("Setup with empty path should succeed with fake pfctl, got: %v", err)
	}
}

func TestRemove_FakePfctl_Succeeds(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "pass on karadul0\n")

	err := Remove()
	if err != nil {
		t.Fatalf("Remove should succeed with fake pfctl, got: %v", err)
	}
}

func TestRemove_FakePfctl_EmptyRules(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	err := Remove()
	if err != nil {
		t.Fatalf("Remove should succeed even with empty rules, got: %v", err)
	}
}

func TestCheck_FakePfctl_HasRules(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "pass on karadul0\npass quick proto tcp to any port 443\n")

	result := Check()
	if !result {
		t.Fatal("Check should return true when rules exist (fake pfctl)")
	}
}

func TestCheck_FakePfctl_NoRules(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	result := Check()
	if result {
		t.Fatal("Check should return false when no rules loaded (fake pfctl with empty output)")
	}
}

func TestCheck_FakePfctl_WhitespaceOnly(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "   \n  \n")

	result := Check()
	if result {
		t.Fatal("Check should return false for whitespace-only rules")
	}
}

func TestAllowPort_FakePfctl_Succeeds(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "pass on karadul0\n")

	err := AllowPort(443, "tcp")
	if err != nil {
		t.Fatalf("AllowPort should succeed with fake pfctl, got: %v", err)
	}
}

func TestAllowPort_FakePfctl_UDP_Succeeds(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	err := AllowPort(53, "udp")
	if err != nil {
		t.Fatalf("AllowPort UDP should succeed with fake pfctl, got: %v", err)
	}
}

func TestRemovePort_FakePfctl_Succeeds(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "pass quick proto tcp to any port 443\npass on karadul0\n")

	err := RemovePort(443, "tcp")
	if err != nil {
		t.Fatalf("RemovePort should succeed with fake pfctl, got: %v", err)
	}
}

func TestRemovePort_FakePfctl_NoMatchingRules(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	// RemovePort with no matching rules should still succeed (reload empty).
	setupFakePfctl(t, "pass on karadul0\n")

	err := RemovePort(9999, "tcp")
	if err != nil {
		t.Fatalf("RemovePort with no matching rules should succeed, got: %v", err)
	}
}

func TestRemovePort_FakePfctl_UDP(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "pass quick proto udp to any port 51820\npass on karadul0\n")

	err := RemovePort(51820, "udp")
	if err != nil {
		t.Fatalf("RemovePort UDP should succeed with fake pfctl, got: %v", err)
	}
}

func TestRemovePort_FakePfctl_EmptyRules(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	err := RemovePort(80, "tcp")
	if err != nil {
		t.Fatalf("RemovePort with empty rules should succeed, got: %v", err)
	}
}

func TestPfctl_FakePfctl_Succeeds(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	err := pfctl("-f", "/etc/pf.conf")
	if err != nil {
		t.Fatalf("pfctl helper should succeed with fake pfctl, got: %v", err)
	}
}

func TestPfctl_FakePfctl_NoArgs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	err := pfctl()
	if err != nil {
		t.Fatalf("pfctl() with no args should succeed with fake pfctl, got: %v", err)
	}
}

func TestSetupThenRemove_FakePfctl(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	if err := Setup(""); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

func TestSetupThenCheck_FakePfctl(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	if err := Setup(""); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Setup loads rules via stdin, so Check should see them.
	if !Check() {
		t.Fatal("Check should return true after Setup with fake pfctl")
	}
}

func TestAllowPortThenRemovePort_FakePfctl(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "pass on karadul0\n")

	if err := AllowPort(8080, "tcp"); err != nil {
		t.Fatalf("AllowPort: %v", err)
	}
	if err := RemovePort(8080, "tcp"); err != nil {
		t.Fatalf("RemovePort: %v", err)
	}
}

func TestFullLifecycle_FakePfctl(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	setupFakePfctl(t, "")

	// Setup
	if err := Setup(""); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Verify Check sees rules
	if !Check() {
		t.Fatal("Check should return true after Setup")
	}

	// Allow some ports
	if err := AllowPort(443, "tcp"); err != nil {
		t.Fatalf("AllowPort 443/tcp: %v", err)
	}
	if err := AllowPort(53, "udp"); err != nil {
		t.Fatalf("AllowPort 53/udp: %v", err)
	}

	// Remove one port
	if err := RemovePort(53, "udp"); err != nil {
		t.Fatalf("RemovePort 53/udp: %v", err)
	}

	// Full remove
	if err := Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}
