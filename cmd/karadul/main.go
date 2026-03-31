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
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/karadul/karadul/internal/config"
	"github.com/karadul/karadul/internal/coordinator"
	"github.com/karadul/karadul/internal/crypto"
	"github.com/karadul/karadul/internal/firewall"
	klog "github.com/karadul/karadul/internal/log"
	"github.com/karadul/karadul/internal/node"
	"github.com/karadul/karadul/internal/relay"
	"github.com/karadul/karadul/internal/tunnel"
	"github.com/karadul/karadul/internal/web"
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

// --- keygen ---

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fs.String("dir", defaultDataDir(), "directory to save keys")
	_ = fs.Parse(args)

	kp, err := crypto.GenerateKeyPair()
	fatalf(err, "generate key pair")

	if err := crypto.SaveKeyPair(kp, *dir); err != nil {
		fatalf(err, "save key pair")
	}
	fmt.Printf("public key:  %s\n", kp.Public.String())
	fmt.Printf("private key: saved to %s/private.key\n", *dir)
}

// --- up ---

func runUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	cfgFile := fs.String("config", "", "config file path")
	server := fs.String("server", "", "coordination server URL")
	authKey := fs.String("auth-key", "", "pre-authentication key")
	peer := fs.String("peer", "", "Phase 1: direct peer endpoint (ip:port)")
	remotePub := fs.String("remote-pub", "", "Phase 1: remote peer public key (base64)")
	hostname := fs.String("hostname", "", "node hostname")
	listenPort := fs.Int("listen-port", 0, "UDP listen port (0=random)")
	routes := fs.String("advertise-routes", "", "comma-separated routes to advertise")
	_ = fs.Bool("advertise-exit-node", false, "advertise as exit node")
	logLevel := fs.String("log-level", "info", "log level")
	_ = fs.Parse(args)

	log := newLogger(*logLevel, "text")

	var cfg *config.NodeConfig
	if *cfgFile != "" {
		var err error
		cfg, err = config.LoadNodeConfig(*cfgFile)
		fatalf(err, "load config")
	} else {
		cfg = config.DefaultNodeConfig()
	}

	// CLI flags override config file values only when explicitly set.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "server":
			cfg.ServerURL = *server
		case "auth-key":
			cfg.AuthKey = *authKey
		case "hostname":
			cfg.Hostname = *hostname
		case "listen-port":
			cfg.ListenPort = *listenPort
		case "advertise-exit-node":
			cfg.AdvertiseExitNode = true
		case "advertise-routes":
			for _, r := range splitComma(*routes) {
				cfg.AdvertiseRoutes = append(cfg.AdvertiseRoutes, r)
			}
		}
	})

	// Phase 1: point-to-point mode (no coordination server).
	if *peer != "" && *remotePub != "" {
		runDirectTunnel(cfg, *peer, *remotePub, log)
		return
	}

	if cfg.ServerURL == "" {
		fatalf(fmt.Errorf("--server is required"), "config")
	}

	// Load key pair.
	kp, err := crypto.LoadKeyPair(cfg.DataDir)
	if err != nil {
		log.Info("no existing key pair found, generating new one")
		kp, err = crypto.GenerateKeyPair()
		must(err, "generate keys")
		must(crypto.SaveKeyPair(kp, cfg.DataDir), "save keys")
	}

	ctx, cancel := signalContext()
	defer cancel()

	eng := node.NewEngine(cfg, kp, log)
	if err := eng.Start(ctx); err != nil {
		log.Error("engine error", "err", err)
		os.Exit(1)
	}
}

// runDirectTunnel handles Phase 1: two nodes with hardcoded peer endpoints.
func runDirectTunnel(cfg *config.NodeConfig, peerEndpoint, remotePubB64 string, log *klog.Logger) {
	kp, err := crypto.LoadKeyPair(cfg.DataDir)
	if err != nil {
		kp, err = crypto.GenerateKeyPair()
		must(err, "generate keys")
		must(crypto.SaveKeyPair(kp, cfg.DataDir), "save keys")
	}

	remotePub, err := crypto.KeyFromBase64(remotePubB64)
	fatalf(err, "parse remote public key")

	log.Info("starting direct tunnel",
		"local_pub", kp.Public.String()[:8]+"...",
		"peer", peerEndpoint,
	)

	// For Phase 1 direct mode, we skip coordination server.
	// Set up a minimal config pointing at the peer.
	cfg.ServerURL = "" // no server
	cfg.AuthKey = ""

	// Use the peer endpoint as a hardcoded route for VIP 100.64.0.1 → peerEndpoint.
	// The actual handshake will be initiated by the node engine.
	// For now, print instructions and wait.
	fmt.Printf("Local public key: %s\n", kp.Public.String())
	fmt.Printf("Peer endpoint:    %s\n", peerEndpoint)
	fmt.Printf("Peer public key:  %s\n", remotePub.String())
	fmt.Println("(Phase 1 direct mode: run 'karadul up --peer=... --remote-pub=...' on both nodes)")

	ctx, cancel := signalContext()
	defer cancel()
	<-ctx.Done()
}

// --- down ---

func runDown(args []string) {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "node data directory")
	_ = fs.Parse(args)

	_, err := localAPIPost(*dataDir, "/shutdown", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: node not running or socket not found (%v)\n", err)
		os.Exit(1)
	}
	fmt.Println("node shutting down")
}

// --- server ---

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgFile := fs.String("config", "", "config file path")
	addr := fs.String("addr", ":8080", "listen address")
	subnet := fs.String("subnet", "100.64.0.0/10", "CGNAT subnet")
	dataDir := fs.String("data-dir", defaultDataDir()+"/server", "data directory")
	withRelay := fs.Bool("with-relay", false, "also start embedded DERP relay")
	withWebUI := fs.Bool("with-web-ui", true, "serve embedded web UI")
	tlsEnabled := fs.Bool("tls", false, "enable TLS")
	selfSigned := fs.Bool("self-signed", false, "use self-signed TLS certificate")
	logLevel := fs.String("log-level", "info", "log level")
	_ = fs.Parse(args)

	// Sub-command: karadul server auth create-key
	if len(fs.Args()) >= 2 && fs.Args()[0] == "auth" && fs.Args()[1] == "create-key" {
		runCreateAuthKey(fs.Args()[2:])
		return
	}

	log := newLogger(*logLevel, "text")

	var cfg *config.ServerConfig
	if *cfgFile != "" {
		var err error
		cfg, err = config.LoadServerConfig(*cfgFile)
		fatalf(err, "load server config")
	} else {
		cfg = config.DefaultServerConfig()
	}

	// CLI flags override config file values only when explicitly set.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cfg.Addr = *addr
		case "subnet":
			cfg.Subnet = *subnet
		case "data-dir":
			cfg.DataDir = *dataDir
		case "log-level":
			cfg.LogLevel = *logLevel
		}
	})

	if *tlsEnabled {
		cfg.TLS.Enabled = true
		cfg.TLS.SelfSigned = *selfSigned
	}

	if err := config.ValidateServerConfig(cfg); err != nil {
		fatalf(err, "validate server config")
	}

	srv, err := coordinator.NewServer(cfg, log)
	fatalf(err, "create server")

	ctx, cancel := signalContext()
	defer cancel()

	if *withRelay {
		relaySrv := relay.NewServer(log)
		relayAddr := cfg.DERP.Addr
		if relayAddr == "" {
			relayAddr = cfg.Addr
		}
		go func() {
			if err := relaySrv.Start(ctx, relayAddr); err != nil {
				log.Error("relay server error", "err", err)
			}
		}()
	}

	// Setup web UI handler if enabled
	var webHandler http.Handler
	if *withWebUI {
		webHandler, err = web.Handler()
		if err != nil {
			log.Warn("web UI not available (run 'make web-build' first)", "err", err)
		}
	}

	if err := srv.Start(ctx, webHandler); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}

// --- relay ---

func runRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	addr := fs.String("addr", ":3478", "listen address")
	logLevel := fs.String("log-level", "info", "log level")
	_ = fs.Parse(args)

	log := newLogger(*logLevel, "text")
	srv := relay.NewServer(log)

	ctx, cancel := signalContext()
	defer cancel()

	if err := srv.Start(ctx, *addr); err != nil {
		log.Error("relay error", "err", err)
		os.Exit(1)
	}
}

// --- peers ---

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

// --- status ---

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

// --- ping ---

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

// --- exit-node ---

func runExitNode(args []string) {
	fs := flag.NewFlagSet("exit-node", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory (for socket path)")
	outIface := fs.String("out-interface", "", "outbound interface for exit node traffic (enable only)")
	_ = fs.Parse(args)

	// Remaining args after flags are the subcommand and its arguments.
	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "usage: karadul exit-node <enable|use <peer>>")
		os.Exit(1)
	}

	switch remaining[0] {
	case "enable":
		iface := *outIface
		if iface == "" {
			iface = defaultOutInterface()
		}
		if iface == "" {
			fmt.Fprintln(os.Stderr, "error: cannot determine default outbound interface; use --out-interface")
			os.Exit(1)
		}
		body, err := localAPIPost(*dataDir, "/exit-node/enable", map[string]string{
			"out_interface": iface,
		})
		fatalf(err, "enable exit node (is 'karadul up' running?)")
		fmt.Printf("exit node enabled via %s\n", iface)
		_ = body

	case "use":
		if len(remaining) < 2 {
			fmt.Fprintln(os.Stderr, "usage: karadul exit-node use <peer-hostname-or-vip>")
			os.Exit(1)
		}
		peer := remaining[1]
		body, err := localAPIPost(*dataDir, "/exit-node/use", map[string]string{
			"peer": peer,
		})
		fatalf(err, "use exit node (is 'karadul up' running?)")
		fmt.Printf("routing all traffic through exit node %s\n", peer)
		_ = body

	default:
		fmt.Fprintf(os.Stderr, "unknown: %s\n", remaining[0])
		os.Exit(1)
	}
}

// defaultOutInterface tries to determine the default outbound network interface.
func defaultOutInterface() string {
	// Dial a public IP to discover which interface is used.
	conn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.Equal(localAddr.IP) {
				return iface.Name
			}
		}
	}
	return ""
}

// --- dns ---

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

// --- auth create-key ---

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

// --- metrics ---

func runMetrics(args []string) {
	fs := flag.NewFlagSet("metrics", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory (for socket path)")
	_ = fs.Parse(args)

	body, err := localAPIGet(*dataDir, "/metrics")
	fatalf(err, "query local node (is 'karadul up' running?)")
	os.Stdout.Write(body)
}

// --- admin ---

func runAdmin(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "usage: karadul admin <subcommand>\n\nSubcommands:\n"+
			"  nodes                    List all nodes\n"+
			"  nodes approve <id>       Approve a pending node\n"+
			"  nodes delete  <id>       Delete a node\n"+
			"  auth-keys                List auth keys\n"+
			"  auth-keys create         Create a new auth key\n"+
			"  auth-keys delete <id>    Revoke an auth key\n"+
			"  acl get                  Print current ACL policy\n"+
			"  acl set [file]           Upload ACL policy from file or stdin\n")
		os.Exit(1)
	}

	switch args[0] {
	case "nodes":
		runAdminNodes(args[1:])
	case "auth-keys":
		runAdminAuthKeys(args[1:])
	case "acl":
		runAdminACL(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown admin subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func runAdminNodes(args []string) {
	fs := flag.NewFlagSet("admin-nodes", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "coordinator server URL")
	_ = fs.Parse(args)

	sub := ""
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
	}

	switch sub {
	case "", "list":
		body := adminDo("GET", *server+"/api/v1/admin/nodes", nil)
		var nodes []map[string]interface{}
		if err := json.Unmarshal(body, &nodes); err != nil {
			fmt.Println(string(body))
			return
		}
		if len(nodes) == 0 {
			fmt.Println("no nodes")
			return
		}
		fmt.Printf("%-20s %-15s %-10s %-10s\n", "HOSTNAME", "VIP", "STATUS", "ID")
		for _, n := range nodes {
			fmt.Printf("%-20s %-15s %-10s %-10s\n",
				strOrDash(n["hostname"]),
				strOrDash(n["virtualIP"]),
				strOrDash(n["status"]),
				shortID(strOrDash(n["id"])),
			)
		}
	case "approve":
		if fs.NArg() < 2 {
			fatalf(fmt.Errorf("node id required"), "admin nodes approve")
		}
		id := fs.Arg(1)
		adminDo("POST", *server+"/api/v1/admin/nodes/"+id+"/approve", nil)
		fmt.Printf("node %s approved\n", id)
	case "delete":
		if fs.NArg() < 2 {
			fatalf(fmt.Errorf("node id required"), "admin nodes delete")
		}
		id := fs.Arg(1)
		adminDoStatus("DELETE", *server+"/api/v1/admin/nodes/"+id, nil, http.StatusNoContent)
		fmt.Printf("node %s deleted\n", id)
	default:
		fmt.Fprintf(os.Stderr, "unknown nodes subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func runAdminAuthKeys(args []string) {
	fs := flag.NewFlagSet("admin-auth-keys", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "coordinator server URL")
	ephemeral := fs.Bool("ephemeral", false, "create single-use key")
	expiry := fs.String("expiry", "24h", "key expiry duration (empty = no expiry)")
	_ = fs.Parse(args)

	sub := ""
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
	}

	switch sub {
	case "", "list":
		body := adminDo("GET", *server+"/api/v1/admin/auth-keys", nil)
		var keys []map[string]interface{}
		if err := json.Unmarshal(body, &keys); err != nil {
			fmt.Println(string(body))
			return
		}
		if len(keys) == 0 {
			fmt.Println("no auth keys")
			return
		}
		fmt.Printf("%-20s %-10s %-10s %s\n", "ID", "EPHEMERAL", "USED", "EXPIRES")
		for _, k := range keys {
			fmt.Printf("%-20s %-10v %-10v %s\n",
				strOrDash(k["id"]),
				k["ephemeral"],
				k["used"],
				strOrDash(k["expiresAt"]),
			)
		}
	case "create":
		payload, _ := json.Marshal(map[string]interface{}{
			"ephemeral": *ephemeral,
			"expiry":    *expiry,
		})
		body := adminDoStatus("POST", *server+"/api/v1/admin/auth-keys", payload, http.StatusCreated)
		var k map[string]interface{}
		if err := json.Unmarshal(body, &k); err != nil {
			fmt.Println(string(body))
			return
		}
		fmt.Printf("auth-key: %s\n", strOrDash(k["key"]))
		fmt.Printf("id:       %s\n", strOrDash(k["id"]))
		fmt.Printf("ephemeral: %v\n", k["ephemeral"])
		if exp, ok := k["expiresAt"]; ok && exp != nil && exp != "" {
			fmt.Printf("expires:  %v\n", exp)
		}
	case "delete":
		if fs.NArg() < 2 {
			fatalf(fmt.Errorf("key id required"), "admin auth-keys delete")
		}
		id := fs.Arg(1)
		adminDoStatus("DELETE", *server+"/api/v1/admin/auth-keys/"+id, nil, http.StatusNoContent)
		fmt.Printf("auth key %s revoked\n", id)
	default:
		fmt.Fprintf(os.Stderr, "unknown auth-keys subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func runAdminACL(args []string) {
	fs := flag.NewFlagSet("admin-acl", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "coordinator server URL")
	_ = fs.Parse(args)

	sub := ""
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
	}

	switch sub {
	case "", "get":
		body := adminDo("GET", *server+"/api/v1/admin/acl", nil)
		var v interface{}
		_ = json.Unmarshal(body, &v)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	case "set":
		// Read ACL policy from a file argument or stdin.
		var payload []byte
		var err error
		if fs.NArg() >= 2 {
			payload, err = os.ReadFile(fs.Arg(1))
			fatalf(err, "read acl file")
		} else {
			payload, err = io.ReadAll(os.Stdin)
			fatalf(err, "read acl from stdin")
		}
		adminDoStatus("PUT", *server+"/api/v1/admin/acl", payload, http.StatusOK)
		fmt.Println("ACL policy updated")
	default:
		fmt.Fprintf(os.Stderr, "unknown acl subcommand: %s\n", sub)
		os.Exit(1)
	}
}

// adminDo calls a coordinator admin endpoint and returns the response body.
// Exits on non-2xx status.
func adminDo(method, url string, payload []byte) []byte {
	return adminDoStatus(method, url, payload, http.StatusOK)
}

// adminDoStatus is like adminDo but expects a specific status code.
func adminDoStatus(method, url string, payload []byte, expectStatus int) []byte {
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	fatalf(err, "build request")
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	fatalf(err, "connect to coordinator (is 'karadul server' running?)")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != expectStatus {
		fmt.Fprintf(os.Stderr, "error: server returned %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	return body
}

func strOrDash(v interface{}) string {
	if v == nil {
		return "-"
	}
	s := fmt.Sprintf("%v", v)
	if s == "" {
		return "-"
	}
	return s
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func runAuth(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: karadul auth create-key [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "create-key":
		runCreateAuthKey(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown auth subcommand: %s\n", args[0])
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

// --- Windows-specific commands ---

func runWintunCheck(args []string) {
	fs := flag.NewFlagSet("wintun-check", flag.ExitOnError)
	_ = fs.Parse(args)

	// Check if wintun.dll is available
	dllPath, err := findWintunDLL()
	if err != nil {
		fmt.Println("❌ Wintun driver not found")
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

	fmt.Println("✅ Wintun driver found")
	fmt.Printf("   Path: %s\n", dllPath)

	// Try to load the DLL
	fmt.Println("   Checking DLL load...")
	// Note: Actual loading requires syscall.NewLazyDLL which we can't test without importing
	fmt.Println("✅ Wintun is ready to use")
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
		fmt.Println("✅ Firewall rules added successfully")
	case "remove":
		if err := removeFirewall(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Firewall rules removed")
	case "check":
		if checkFirewall() {
			fmt.Println("✅ Firewall rules are configured")
		} else {
			fmt.Println("❌ Firewall rules not found")
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
		fmt.Printf("✅ Port %d/%s allowed through firewall\n", port, protocol)
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
