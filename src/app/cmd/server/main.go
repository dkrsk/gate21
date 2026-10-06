package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gate21/src/app/broker"
	"gate21/src/app/config"
	"gate21/src/app/httpx"
	"gate21/src/app/proxy"
	"gate21/src/app/registry"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	if err := run(logger); err != nil {
		logger.Fatalf("fatal: %v", err)
	}
}

func run(logger *log.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	reg, err := registry.Load(cfg.ClientsPath)
	if err != nil {
		return err
	}

	kc, err := proxy.New(cfg.KeycloakBase, cfg.KeycloakRealm, cfg.HTTPTimeout)
	if err != nil {
		return err
	}

	br, err := broker.New(broker.Options{
		Logger:        logger,
		Keycloak:      kc,
		Registry:      reg,
		SignerKey:     []byte(cfg.CookieKey),
		FlowMaxAge:    cfg.FlowMaxAge,
		CodeTTL:       cfg.CodeTTL,
		DeviceTTL:     cfg.DeviceTTL,
		PollInterval:  cfg.PollInterval,
		PublicBase:    cfg.PublicBase,
		SecureCookies: cfg.SecureCookies,
	})
	if err != nil {
		return err
	}
	defer br.Close()

	var handler http.Handler = br.Routes()
	handler = httpx.WithRequestID(handler)
	handler = httpx.Recover(logger)(handler)
	handler = httpx.AccessLog(logger)(handler)
	handler = httpx.RateLimit(10, 30)(handler)

	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(handleHealthz))
	mux.Handle("/", handler)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      25 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s", cfg.ListenAddr)
		errCh <- srv.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	logger.Print("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return nil
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}
