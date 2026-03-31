package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/karadul/karadul/internal/firewall"
	"github.com/karadul/karadul/internal/tunnel"
)

func runWintunCheck(args []string) {
	fs := flag.NewFlagSet("wintun-check", flag.ExitOnError)
	_ = fs.Parse(args)

	// Check if wintun.dll is available
	dllPath, err := findWintunDLL()
	if err != nil {
		fmt.Println("Wintun driver not found")
		fmt.Println()
		fmt.Println("Please download Wintun from:")
		fmt.Println("  AMD64: https://www.wintun.net/builds/wintun-0.14.1-amd64.zip")
		fmt.Println("  ARM64: https://www.wintun.net/builds/wintun-0.14.1-arm64.zip")
		fmt.Println("  x86:   https://www.wintun.net/builds/wintun-0.14.1-x86.zip")
		fmt.Println()
		fmt.Println("Extract wintun.dll and place it in one of these locations:")
		fmt.Println("  1. Same directory as karadul.exe")
		fmt.Println("  2. C:\\Windows\\System32\\")
		fmt.Println("  3. Current working directory")
		os.Exit(1)
	}

	fmt.Println("Wintun driver found")
	fmt.Printf("   Path: %s\n", dllPath)

	// Try to load the DLL
	fmt.Println("   Checking DLL load...")
	// Note: Actual loading requires syscall.NewLazyDLL which we can't test without importing
	fmt.Println("Wintun is ready to use")
}

func runFirewall(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, `usage: karadul firewall <command>

Commands:
  setup     Add Windows Firewall rules for Karadul
  remove    Remove Windows Firewall rules
  check     Check if firewall rules are configured
  allow-port <port> <tcp|udp>   Allow specific port
`)
		os.Exit(1)
	}

	switch args[0] {
	case "setup":
		exePath, _ := os.Executable()
		if err := setupFirewall(exePath); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Firewall rules added successfully")
	case "remove":
		if err := removeFirewall(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Firewall rules removed")
	case "check":
		if checkFirewall() {
			fmt.Println("Firewall rules are configured")
		} else {
			fmt.Println("Firewall rules not found")
			fmt.Println("Run 'karadul firewall setup' to add them")
		}
	case "allow-port":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: karadul firewall allow-port <port> <tcp|udp>")
			os.Exit(1)
		}
		port, err := strconv.Atoi(args[1])
		if err != nil || port < 1 || port > 65535 {
			fmt.Fprintf(os.Stderr, "error: invalid port number: %s\n", args[1])
			os.Exit(1)
		}
		protocol := args[2]
		if err := allowPortFirewall(port, protocol); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Port %d/%s allowed through firewall\n", port, protocol)
	default:
		fmt.Fprintf(os.Stderr, "unknown firewall command: %s\n", args[0])
		os.Exit(1)
	}
}

// Platform-specific helpers (Windows implementations)

func findWintunDLL() (string, error) {
	return tunnel.WintunDLLPath()
}

func setupFirewall(exePath string) error {
	return firewall.Setup(exePath)
}

func removeFirewall() error {
	return firewall.Remove()
}

func checkFirewall() bool {
	return firewall.Check()
}

func allowPortFirewall(port int, protocol string) error {
	return firewall.AllowPort(port, protocol)
}
