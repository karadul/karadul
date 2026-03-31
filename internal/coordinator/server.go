package coordinator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/karadul/karadul/internal/config"
	klog "github.com/karadul/karadul/internal/log"
)

// Server is the Karadul coordination server.
type Server struct {
	cfg     *config.ServerConfig
	store   *Store
	pool    *IPPool
	poller  *Poller
	api     *API
	hub     *Hub
	httpSrv *http.Server
	log     *klog.Logger
}

// NewServer creates a coordination Server from cfg.
func NewServer(cfg *config.ServerConfig, log *klog.Logger) (*Server, error) {
	storePath := cfg.DataDir + "/state.json"
	store, err := NewStore(storePath)
	if err != nil {
		return nil, fmt.Errorf("init store: %w", err)
	}

	pool, err := NewIPPool(cfg.Subnet)
	if err != nil {
		return nil, fmt.Errorf("init ip pool: %w", err)
	}

	// Re-reserve IPs for already-registered nodes.
	for _, node := range store.ListNodes() {
		ip := net.ParseIP(node.VirtualIP)
		if ip != nil {
			_ = pool.Reserve(node.ID, ip)
		}
	}

	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, cfg.ApprovalMode, cfg)
	hub := NewHub(store, cfg.AllowedOrigins)

	// Wire up DERPMap builder so poll responses include relay info.
	poller.SetDERPMapFn(api.buildDERPMap)

	return &Server{
		cfg:    cfg,
		store:  store,
		pool:   pool,
		poller: poller,
		api:    api,
		hub:    hub,
		log:    log,
	}, nil
}

// Start begins listening and serving. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context, webHandler http.Handler) error {
	mux := http.NewServeMux()
	s.api.RegisterRoutes(mux)

	// Health check.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// WebSocket endpoint
	mux.HandleFunc("/ws", s.hub.ServeWS)

	// Web UI handler (if provided)
	if webHandler != nil {
		mux.Handle("/", webHandler)
	}

	// Start WebSocket hub in background
	go s.hub.Run()

	handler, cleanupBuckets := rateLimitMiddleware(mux, s.cfg.RateLimit)

	// Start stale bucket cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cleanupBuckets()
			case <-ctx.Done():
				return
			}
		}
	}()

	handler = loggingMiddleware(handler, s.log)

	s.httpSrv = &http.Server{
		Addr:         s.cfg.Addr,
		Handler:      handler,
		ReadTimeout:  35 * time.Second,
		WriteTimeout: 35 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	var ln net.Listener
	var err error

	if s.cfg.TLS.Enabled {
		tlsCfg, tlsErr := s.tlsConfig()
		if tlsErr != nil {
			return fmt.Errorf("tls config: %w", tlsErr)
		}
		ln, err = tls.Listen("tcp", s.cfg.Addr, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", s.cfg.Addr)
	}
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Addr, err)
	}

	s.log.Info("coordination server started", "addr", s.cfg.Addr, "tls", s.cfg.TLS.Enabled)
	if s.cfg.AdminSecret == "" {
		s.log.Warn("admin endpoints are UNPROTECTED — set admin_secret in config for production use")
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		s.api.Close()
		s.hub.Close()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutCtx)
	case err := <-errCh:
		s.api.Close()
		s.hub.Close()
		return err
	}
}

// tlsConfig builds a *tls.Config, generating a self-signed cert if needed.
func (s *Server) tlsConfig() (*tls.Config, error) {
	if s.cfg.TLS.SelfSigned || (s.cfg.TLS.CertFile == "" && s.cfg.TLS.KeyFile == "") {
		cert, err := generateSelfSignedCert()
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// generateSelfSignedCert creates a minimal self-signed TLS certificate.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "karadul"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// Store returns the server's state store (for admin operations).
func (s *Server) Store() *Store { return s.store }

// --- Middleware ---

// rateLimitMiddleware is a simple per-IP token bucket rate limiter.
// Returns the handler, the buckets map, and a cleanup function.
func rateLimitMiddleware(next http.Handler, rps int) (http.Handler, func()) {
	if rps <= 0 {
		return next, func() {}
	}

	type bucket struct {
		tokens   float64
		lastFill time.Time
		mu       sync.Mutex
	}

	var mu sync.Mutex
	buckets := make(map[string]*bucket)

	refill := func(b *bucket) {
		b.mu.Lock()
		defer b.mu.Unlock()
		now := time.Now()
		elapsed := now.Sub(b.lastFill).Seconds()
		b.tokens += elapsed * float64(rps)
		if b.tokens > float64(rps) {
			b.tokens = float64(rps)
		}
		b.lastFill = now
	}

	cleanup := func() {
		mu.Lock()
		defer mu.Unlock()
		for ip, b := range buckets {
			b.mu.Lock()
			if time.Since(b.lastFill) > 5*time.Minute {
				delete(buckets, ip)
			}
			b.mu.Unlock()
		}
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)

		mu.Lock()
		b, ok := buckets[ip]
		if !ok {
			b = &bucket{tokens: float64(rps), lastFill: time.Now()}
			buckets[ip] = b
		}
		mu.Unlock()

		refill(b)

		b.mu.Lock()
		if b.tokens < 1 {
			b.mu.Unlock()
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		b.tokens--
		b.mu.Unlock()

		next.ServeHTTP(w, r)
	})

	return handler, cleanup
}

// loggingMiddleware logs every HTTP request.
func loggingMiddleware(next http.Handler, log *klog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.code,
			"duration", time.Since(start).String(),
			"remote", r.RemoteAddr,
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}
