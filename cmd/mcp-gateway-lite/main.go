// Command mcp-gateway-lite is a single-binary, stateless reverse
// proxy for MCP (Model Context Protocol) Streamable HTTP servers with
// a JSON Lines audit trail.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bharat3645/mcp-gateway-lite/gateway"
)

// upstreamFlags collects repeatable --upstream name=url flags.
type upstreamFlags []gateway.Upstream

func (u *upstreamFlags) String() string {
	return fmt.Sprintf("%d upstream(s)", len(*u))
}

func (u *upstreamFlags) Set(v string) error {
	up, err := gateway.ParseUpstreamFlag(v)
	if err != nil {
		return err
	}
	*u = append(*u, up)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-gateway-lite:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("mcp-gateway-lite", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to JSON config file")
	listen := fs.String("listen", "", "listen address (overrides config; default "+gateway.DefaultListen+")")
	auditPath := fs.String("audit", "", "audit JSONL destination (overrides config; default stdout)")
	showVersion := fs.Bool("version", false, "print version and exit")
	checkOnly := fs.Bool("check", false, "validate configuration and exit")
	var ups upstreamFlags
	fs.Var(&ups, "upstream", "upstream as name=url (repeatable, adds to config upstreams)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if *showVersion {
		fmt.Fprintln(stdout, "mcp-gateway-lite", gateway.Version)
		return nil
	}

	var cfg gateway.Config
	if *configPath != "" {
		loaded, err := gateway.Load(*configPath)
		if err != nil {
			return err
		}
		cfg = loaded
	}
	cfg.Upstreams = append(cfg.Upstreams, ups...)
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *auditPath != "" {
		cfg.Audit.Path = *auditPath
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	if *checkOnly {
		fmt.Fprintf(stdout, "config ok: listen=%s upstreams=%d\n", cfg.Listen, len(cfg.Upstreams))
		return nil
	}

	auditor, err := gateway.NewAuditor(cfg.Audit)
	if err != nil {
		return err
	}
	defer auditor.Close()

	gw, err := gateway.New(cfg, auditor)
	if err != nil {
		return err
	}

	srv := &http.Server{}
	srv.Addr = cfg.Listen
	srv.Handler = gw
	srv.ReadHeaderTimeout = 10 * time.Second

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "mcp-gateway-lite %s listening on %s (%d upstreams)\n", gateway.Version, cfg.Listen, len(cfg.Upstreams))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
