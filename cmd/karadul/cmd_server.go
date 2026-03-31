package main

import (
	"encoding/base64"
	"flag"
	"net/http"
	"os"

	"github.com/karadul/karadul/internal/config"
	"github.com/karadul/karadul/internal/coordinator"
	"github.com/karadul/karadul/internal/relay"
	"github.com/karadul/karadul/internal/web"
)

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
		// Wire up client verification: only allow registered nodes.
		coordStore := srv.Store()
		relaySrv.VerifyFunc = func(pubKey [32]byte) bool {
			pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])
			_, ok := coordStore.GetNodeByPubKey(pubKeyB64)
			return ok
		}
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
