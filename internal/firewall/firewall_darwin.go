//go:build darwin

package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

const anchorName = "com.karadul"

// Setup configures firewall rules on macOS using pfctl.
// It creates a pf anchor and loads basic rules for TUN traffic.
func Setup(exePath string) error {
	// Ensure the anchor exists in the main ruleset.
	// Add anchor reference to /etc/pf.conf (idempotent).
	if err := pfctl("-f", "/etc/pf.conf"); err != nil {
		// pf.conf may not exist in some setups; continue anyway.
		_ = err
	}

	// Load karadul rules into the anchor.
	rules := fmt.Sprintf(
		"pass on karadul0\n"+
			"pass quick inet from 100.64.0.0/10 to any\n"+
			"pass quick inet from any to 100.64.0.0/10\n",
	)

	// Use pfctl to load rules into the anchor.
	cmd := exec.Command("pfctl", "-a", anchorName, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl load anchor: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Enable pf if not already enabled.
	_, _ = exec.Command("pfctl", "-e").CombinedOutput()

	return nil
}

// Remove deletes the karadul pf anchor and its rules.
func Remove() error {
	// Flush the anchor rules.
	if out, err := exec.Command("pfctl", "-a", anchorName, "-F", "rules").CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl flush anchor: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Check returns true if the karadul pf anchor has rules loaded.
func Check() bool {
	out, err := exec.Command("pfctl", "-a", anchorName, "-s", "rules").CombinedOutput()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}

// AllowPort adds a firewall rule for a specific port via the pf anchor.
func AllowPort(port int, protocol string) error {
	p := strings.ToLower(protocol)
	if p != "tcp" && p != "udp" {
		return fmt.Errorf("unsupported protocol %q; use tcp or udp", protocol)
	}

	// Append rule to the anchor.
	rule := fmt.Sprintf("pass quick proto %s to any port %d\n", p, port)
	cmd := exec.Command("pfctl", "-a", anchorName, "-f", "-")
	// First get existing rules, then append new one.
	existing, _ := exec.Command("pfctl", "-a", anchorName, "-s", "rules").CombinedOutput()
	cmd.Stdin = strings.NewReader(string(existing) + rule)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl allow port: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// RemovePort removes a port-specific firewall rule from the pf anchor.
func RemovePort(port int, protocol string) error {
	p := strings.ToLower(protocol)
	if p != "tcp" && p != "udp" {
		return fmt.Errorf("unsupported protocol %q; use tcp or udp", protocol)
	}

	// Get existing rules, filter out the one we want to remove, reload.
	out, err := exec.Command("pfctl", "-a", anchorName, "-s", "rules").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl list rules: %w", err)
	}

	target := fmt.Sprintf("port %d", port)
	var kept []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, target) && strings.Contains(line, p) {
			continue
		}
		kept = append(kept, line)
	}

	// Reload remaining rules.
	var rules string
	if len(kept) > 0 {
		rules = strings.Join(kept, "\n") + "\n"
	}
	cmd := exec.Command("pfctl", "-a", anchorName, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl remove port: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// pfctl runs a pfctl command.
func pfctl(args ...string) error {
	out, err := exec.Command("pfctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}
