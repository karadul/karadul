// Command karadul is the Karadul mesh VPN client and server.
//
// Usage:
//
//	karadul keygen                           Generate a new key pair
//	karadul up [flags]                       Start as a mesh node
//	karadul server [flags]                   Start as a coordination server
//	karadul relay [flags]                    Start as a DERP relay
//	karadul peers                            List connected peers
//	karadul status                           Show node status
//	karadul ping <peer>                      Ping a peer through the mesh
//	karadul exit-node enable                 Enable this node as exit node
//	karadul exit-node use <peer>             Use a peer as exit node
//	karadul dns                              Show MagicDNS entries
//	karadul auth create-key [flags]          Create a pre-authentication key
//	karadul metrics                          Show Prometheus-format node metrics
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	klog "github.com/karadul/karadul/internal/log"
)

const version = "0.1.0-beta.1"

// buildInfo returns git commit and build date from embedded VCS metadata.
func buildInfo() (commit, date string) {
	commit, date = "unknown", "unknown"
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 8 {
				commit = s.Value[:8]
			} else if s.Value != "" {
				commit = s.Value
			}
		case "vcs.time":
			date = s.Value
		}
	}
	return
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "keygen":
		runKeygen(args)
	case "up":
		runUp(args)
	case "down":
		runDown(args)
	case "server":
		runServer(args)
	case "relay":
		runRelay(args)
	case "peers":
		runPeers(args)
	case "status":
		runStatus(args)
	case "ping":
		runPing(args)
	case "exit-node":
		runExitNode(args)
	case "dns":
		runDNS(args)
	case "auth":
		runAuth(args)
	case "admin":
		runAdmin(args)
	case "metrics":
		runMetrics(args)
	case "version":
		commit, date := buildInfo()
		fmt.Printf("karadul %s (commit %s, built %s)\n", version, commit, date)
	case "wintun-check":
		runWintunCheck(args)
	case "firewall":
		runFirewall(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

// --- helpers ---

func usage() {
	fmt.Fprintf(os.Stderr, `Karadul — self-hosted mesh VPN

Usage:
  karadul <command> [flags]

Commands:
  keygen                Generate a new node key pair
  up                    Start as a mesh node
  down                  Stop a running mesh node
  server                Start the coordination server
  relay                 Start a DERP relay server
  peers                 List mesh peers
  status                Show node status
  ping <peer>           Ping a peer
  exit-node             Manage exit node
  dns                   Show MagicDNS entries
  metrics               Show Prometheus-format node metrics
  auth create-key       Create a pre-authentication key
  admin                 Manage coordinator (nodes, auth-keys, acl)
  wintun-check          Check Wintun driver status (Windows)
  firewall              Manage Windows firewall rules
  version               Print version

Run 'karadul <command> -help' for command flags.
`)
}

func fatalf(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", msg, err)
		os.Exit(1)
	}
}

// must is like fatalf but always exits. Use for calls after a fatalf that
// should never be reached on the error path.
func must(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", msg, err)
		os.Exit(1)
	}
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" {
		fmt.Fprintf(os.Stderr, "error: cannot determine home directory (set $HOME)\n")
		os.Exit(1)
	}
	return filepath.Join(home, ".karadul")
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

func newLogger(level, format string) *klog.Logger {
	lvl := klog.ParseLevel(level)
	var fmt klog.Format
	if format == "json" {
		fmt = klog.FormatJSON
	}
	return klog.New(os.Stderr, lvl, fmt)
}

// localAPIGet calls an endpoint on the node's local Unix socket and returns
// the response body. This is how CLI commands communicate with a running node.
func localAPIGet(dataDir, path string) ([]byte, error) {
	sockPath := filepath.Join(dataDir, "karadul.sock")
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}
	resp, err := client.Get("http://karadul" + path)
	if err != nil {
		return nil, fmt.Errorf("connect to node socket %s: %w", sockPath, err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// localAPIPost sends a JSON-encoded payload to an endpoint on the node's local
// Unix socket and returns the response body.
func localAPIPost(dataDir, path string, payload interface{}) ([]byte, error) {
	sockPath := filepath.Join(dataDir, "karadul.sock")
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}
	resp, err := client.Post("http://karadul"+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("connect to node socket %s: %w", sockPath, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

func splitComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if i > start {
				result = append(result, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}
