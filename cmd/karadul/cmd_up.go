package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/karadul/karadul/internal/config"
	"github.com/karadul/karadul/internal/crypto"
	klog "github.com/karadul/karadul/internal/log"
	"github.com/karadul/karadul/internal/node"
)

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
