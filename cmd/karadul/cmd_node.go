package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/karadul/karadul/internal/coordinator"
)

func runPeers(args []string) {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory (for socket path)")
	_ = fs.Parse(args)

	body, err := localAPIGet(*dataDir, "/peers")
	fatalf(err, "query local node (is 'karadul up' running?)")

	type peerInfo struct {
		Hostname  string `json:"hostname"`
		NodeID    string `json:"nodeId"`
		VirtualIP string `json:"virtualIp"`
		State     string `json:"state"`
		Endpoint  string `json:"endpoint,omitempty"`
	}
	var peers []peerInfo
	fatalf(json.Unmarshal(body, &peers), "decode peers")

	if len(peers) == 0 {
		fmt.Println("no peers")
		return
	}
	fmt.Printf("%-20s %-15s %-20s %-12s %s\n", "HOSTNAME", "VIP", "ENDPOINT", "STATE", "NODE-ID")
	for _, p := range peers {
		ep := p.Endpoint
		if ep == "" {
			ep = "(relay)"
		}
		fmt.Printf("%-20s %-15s %-20s %-12s %s\n",
			p.Hostname, p.VirtualIP, ep, p.State, p.NodeID[:8])
	}
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory (for socket path)")
	_ = fs.Parse(args)

	body, err := localAPIGet(*dataDir, "/status")
	fatalf(err, "query local node (is 'karadul up' running?)")

	// Pretty-print JSON.
	var v interface{}
	_ = json.Unmarshal(body, &v)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func runPing(args []string) {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	count := fs.Int("c", 4, "number of pings")
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: karadul ping <peer-hostname-or-vip>")
		os.Exit(1)
	}
	target := fs.Arg(0)

	// Try the local API socket first.
	sockPath := *dataDir + "/karadul.sock"
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
		Timeout: 5 * time.Second,
	}

	// Resolve target to virtual IP via local peers API.
	resp, err := client.Get("http://unix/peers")
	if err != nil {
		fmt.Fprintf(os.Stderr, "karadul ping: cannot reach local API (is 'karadul up' running?): %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var peers []struct {
		Hostname  string `json:"hostname"`
		VirtualIP string `json:"virtualIp"`
		State     string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		fmt.Fprintf(os.Stderr, "karadul ping: failed to parse peers: %v\n", err)
		os.Exit(1)
	}

	// Find the target peer.
	var targetIP string
	for _, p := range peers {
		if p.Hostname == target || p.VirtualIP == target {
			targetIP = p.VirtualIP
			break
		}
	}
	if targetIP == "" {
		fmt.Fprintf(os.Stderr, "karadul ping: peer %q not found\n", target)
		os.Exit(1)
	}

	fmt.Printf("PING %s (%s) via karadul mesh\n", target, targetIP)

	// Use ICMP via the TUN interface.
	success := 0
	rtts := []time.Duration{}
	for i := 0; i < *count; i++ {
		start := time.Now()
		// Use the system ping with a single count and timeout.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", targetIP)
		output, err := cmd.CombinedOutput()
		cancel()
		elapsed := time.Since(start)

		if err == nil {
			success++
			rtts = append(rtts, elapsed)
			fmt.Printf("64 bytes from %s: icmp_seq=%d time=%v\n", targetIP, i+1, elapsed.Round(time.Microsecond))
		} else {
			fmt.Printf("From %s: icmp_seq=%d Request timeout\n", targetIP, i+1)
			_ = output
		}
		time.Sleep(1 * time.Second)
	}

	fmt.Printf("\n--- %s ping statistics ---\n", target)
	fmt.Printf("%d packets transmitted, %d received, %.0f%% packet loss\n",
		*count, success, float64(*count-success)/float64(*count)*100)
	if len(rtts) > 0 {
		var min, max, total time.Duration
		min = rtts[0]
		for _, r := range rtts {
			total += r
			if r < min {
				min = r
			}
			if r > max {
				max = r
			}
		}
		fmt.Printf("rtt min/avg/max = %v/%v/%v\n",
			min.Round(time.Microsecond),
			(total/time.Duration(len(rtts))).Round(time.Microsecond),
			max.Round(time.Microsecond))
	}
}

func runDNS(args []string) {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	_ = fs.Parse(args)

	// The local API doesn't expose DNS entries yet — use /peers as a proxy.
	body, err := localAPIGet(*dataDir, "/peers")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v (is 'karadul up' running?)\n", err)
		os.Exit(1)
	}
	type peerInfo struct {
		Hostname  string `json:"hostname"`
		VirtualIP string `json:"virtualIp"`
	}
	var peers []peerInfo
	_ = json.Unmarshal(body, &peers)
	if len(peers) == 0 {
		fmt.Println("no MagicDNS entries")
		return
	}
	fmt.Printf("%-30s %s\n", "NAME", "IP")
	for _, p := range peers {
		fmt.Printf("%-30s %s\n",
			p.Hostname+".web.karadul.", p.VirtualIP)
	}
}

func runMetrics(args []string) {
	fs := flag.NewFlagSet("metrics", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory (for socket path)")
	_ = fs.Parse(args)

	body, err := localAPIGet(*dataDir, "/metrics")
	fatalf(err, "query local node (is 'karadul up' running?)")
	os.Stdout.Write(body)
}

// runCreateAuthKey is referenced by both cmd_server.go and cmd_keygen.go.
// It is placed here alongside other node/auth operations.
func runCreateAuthKey(args []string) {
	fs := flag.NewFlagSet("auth-create-key", flag.ExitOnError)
	server := fs.String("server", "", "coordination server URL (for remote creation)")
	ephemeral := fs.Bool("ephemeral", false, "single-use key")
	expiry := fs.Duration("expiry", 24*time.Hour, "key expiry (e.g. 24h, 0=never)")
	_ = fs.Parse(args)
	_ = server

	// Generate key locally and print.
	k, err := coordinator.GenerateAuthKey(*ephemeral, *expiry)
	fatalf(err, "generate auth key")

	fmt.Printf("auth-key: %s\n", k.Key)
	fmt.Printf("id:       %s\n", k.ID)
	fmt.Printf("ephemeral: %v\n", k.Ephemeral)
	if !k.ExpiresAt.IsZero() {
		fmt.Printf("expires:  %s\n", k.ExpiresAt.Format(time.RFC3339))
	}
}
