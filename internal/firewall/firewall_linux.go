//go:build linux

package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

const chainName = "KARADUL"

// Setup configures firewall rules on Linux using iptables.
// It creates a dedicated KARADUL chain and adds rules for TUN traffic.
func Setup(exePath string) error {
	// Create the KARADUL chain (ignore error if it already exists).
	_, _ = exec.Command("iptables", "-t", "filter", "-N", chainName).CombinedOutput()

	// Add jump rules from INPUT and OUTPUT (idempotent — we check first).
	if !chainHasJump("INPUT") {
		if err := ipt("INPUT", "-j", chainName); err != nil {
			return fmt.Errorf("iptables jump INPUT: %w", err)
		}
	}
	if !chainHasJump("OUTPUT") {
		if err := ipt(chainName, "-j", "RETURN"); err != nil {
			// no-op rule so empty chain doesn't block traffic
			_ = err
		}
		if err := ipt("OUTPUT", "-j", chainName); err != nil {
			return fmt.Errorf("iptables jump OUTPUT: %w", err)
		}
	}

	// Allow traffic on the TUN interface.
	if err := ipt(chainName, "-i", "karadul0", "-j", "ACCEPT"); err != nil {
		// Non-fatal — TUN might not be up yet.
		_ = err
	}
	if err := ipt(chainName, "-o", "karadul0", "-j", "ACCEPT"); err != nil {
		_ = err
	}

	return nil
}

// Remove deletes the KARADUL iptables chain and all associated rules.
func Remove() error {
	// Flush the chain first.
	_, _ = exec.Command("iptables", "-F", chainName).CombinedOutput()

	// Delete jump rules from INPUT/OUTPUT.
	deleteJumpFrom("INPUT")
	deleteJumpFrom("OUTPUT")

	// Delete the chain.
	_, err := exec.Command("iptables", "-X", chainName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables delete chain %s: %w", chainName, err)
	}
	return nil
}

// Check returns true if the KARADUL chain exists with rules.
func Check() bool {
	out, err := exec.Command("iptables", "-nL", chainName).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "ACCEPT")
}

// AllowPort adds a firewall rule for a specific port.
func AllowPort(port int, protocol string) error {
	p := strings.ToLower(protocol)
	if p != "tcp" && p != "udp" {
		return fmt.Errorf("unsupported protocol %q; use tcp or udp", protocol)
	}
	return ipt(chainName, "-p", p, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT",
		"-m", "comment", "--comment", fmt.Sprintf("karadul-port-%d", port))
}

// RemovePort removes a port-specific firewall rule.
func RemovePort(port int, protocol string) error {
	p := strings.ToLower(protocol)
	if p != "tcp" && p != "udp" {
		return fmt.Errorf("unsupported protocol %q; use tcp or udp", protocol)
	}
	return ipt("-D", chainName, "-p", p, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT",
		"-m", "comment", "--comment", fmt.Sprintf("karadul-port-%d", port))
}

// ipt runs an iptables append command.
func ipt(args ...string) error {
	fullArgs := append([]string{"-A"}, args...)
	out, err := exec.Command("iptables", fullArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %s", strings.Join(fullArgs, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// chainHasJump checks whether chain contains a jump to our chain.
func chainHasJump(parentChain string) bool {
	out, _ := exec.Command("iptables", "-nL", parentChain).CombinedOutput()
	return strings.Contains(string(out), chainName)
}

// deleteJumpFrom removes the jump to KARADUL from the given parent chain.
func deleteJumpFrom(parent string) {
	_, _ = exec.Command("iptables", "-D", parent, "-j", chainName).CombinedOutput()
}
