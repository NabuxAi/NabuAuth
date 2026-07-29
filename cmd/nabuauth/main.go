// Command nabuauth starts the NabuAuth single sign-on server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nabuauth/internal/config"
	"nabuauth/internal/server"
	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

func main() {
	configPath := flag.String("config", envOr("NABUAUTH_CONFIG", "apps.yaml"), "path to the YAML config file")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("failed to load config", "path", *configPath, "error", err)
		os.Exit(1)
	}

	dsn := databaseURL()
	if dsn == "" {
		log.Error("no database configured: set DATABASE_URL, or DB_HOST/DB_DATABASE/DB_USERNAME/DB_PASSWORD")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, dsn)
	if err != nil {
		log.Error("database unavailable", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	keys, err := loadKeyring(ctx, st)
	if err != nil {
		log.Error("could not load signing keys", "error", err)
		os.Exit(1)
	}

	srv, err := server.New(cfg, st, keys, log)
	if err != nil {
		log.Error("could not start server", "error", err)
		os.Exit(1)
	}
	if err := srv.SyncApps(ctx); err != nil {
		log.Error("could not register ecosystem apps", "error", err)
		os.Exit(1)
	}

	appIDs := make([]string, 0, len(cfg.Apps))
	for _, a := range cfg.Apps {
		appIDs = append(appIDs, a.ID)
	}
	log.Info("nabuauth starting",
		"port", cfg.Server.Port,
		"issuer", cfg.Server.Issuer,
		"signing_key", keys.SigningKID(),
		"apps", appIDs,
		"registration_open", cfg.Server.AllowRegistration,
	)

	// Expired codes, tokens and sessions accumulate forever otherwise; the sweep
	// is cheap and keeps the tables from becoming the biggest thing in the
	// database.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.Cleanup(context.Background()); err != nil {
					log.Warn("cleanup", "error", err)
				}
			}
		}
	}()

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Warn("shutdown", "error", err)
	}
}

// loadKeyring reads the signing keys, generating one on first boot so a fresh
// deployment issues valid tokens with no manual key ceremony.
func loadKeyring(ctx context.Context, st *store.Store) (*tokens.Keyring, error) {
	stored, err := st.ActiveSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	if len(stored) == 0 {
		kid, pem, err := tokens.GenerateKey()
		if err != nil {
			return nil, err
		}
		if err := st.InsertSigningKey(ctx, store.SigningKey{KID: kid, PrivatePEM: pem}); err != nil {
			return nil, err
		}
		// Re-read rather than trusting the local copy: two replicas booting at
		// once both insert, and only one row wins.
		if stored, err = st.ActiveSigningKeys(ctx); err != nil {
			return nil, err
		}
	}
	keys := make([]struct{ KID, PEM string }, 0, len(stored))
	for _, k := range stored {
		keys = append(keys, struct{ KID, PEM string }{k.KID, k.PrivatePEM})
	}
	return tokens.NewKeyring(keys)
}

// databaseURL builds the connection string, accepting either a single
// DATABASE_URL or the discrete DB_* variables the compose file already sets.
func databaseURL() string {
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		return dsn
	}
	host := envOr("DB_HOST", "")
	if host == "" {
		return ""
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		os.Getenv("DB_USERNAME"),
		os.Getenv("DB_PASSWORD"),
		host,
		envOr("DB_PORT", "5432"),
		envOr("DB_DATABASE", "nabuauth"),
		envOr("DB_SSLMODE", "disable"),
	)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
