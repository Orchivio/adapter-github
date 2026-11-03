// Command orchivio-github-adapter serves the CodeHostAdapter gRPC service backed by a GitHub App.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	pluginv1 "github.com/soemii/orchivio-server/contract/gen/orchivio/plugin/v1"
	"github.com/soemii/orchivio-server/contract/secretref"
	"google.golang.org/grpc"

	"github.com/soemii/orchivio-adapter-github/internal/github"
	"github.com/soemii/orchivio-adapter-github/internal/server"
)

const (
	defaultAPI    = "https://api.github.com"
	defaultCloneB = "https://github.com"
	defaultAddr   = ":7201"
	stopTimeout   = 10 * time.Second
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func run(log *slog.Logger) error {
	appID, err := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)
	if err != nil {
		return fmt.Errorf("GITHUB_APP_ID must be an integer")
	}
	pemText, err := secretref.Env{Lookup: os.LookupEnv}.Resolve(os.Getenv("GITHUB_APP_PRIVATE_KEY_REF"))
	if err != nil {
		return fmt.Errorf("resolve GITHUB_APP_PRIVATE_KEY_REF: %w", err)
	}
	key, err := github.ParsePrivateKey(pemText)
	if err != nil {
		return err
	}
	app := github.NewApp(env("GITHUB_API_URL", defaultAPI), appID, key, time.Now, nil)
	lis, err := net.Listen("tcp", env("ORCHIVIO_GRPC_ADDR", defaultAddr))
	if err != nil {
		return err
	}
	// ponytail: insecure gRPC (dev, localhost); add TLS/mTLS before exposing beyond the host.
	g := grpc.NewServer()
	pluginv1.RegisterCodeHostAdapterServer(g, server.New(app, defaultCloneB))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 1)
	go func() { errs <- g.Serve(lis) }()
	log.Info("github adapter listening", "addr", lis.Addr().String())
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	done := make(chan struct{})
	go func() { g.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(stopTimeout):
		g.Stop()
	}
	return nil
}
