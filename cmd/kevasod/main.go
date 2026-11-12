// Command kevasod is the agent on every host. Until M2 it has one mode, for development:
//
//	kevasod dev [--listen 127.0.0.1:8080] [--data PATH]
//
// which serves the API (no auth, loopback only) over a SQLite store, so `kvo` has something to
// talk to. M2 replaces it with the real control-plane component (TLS, admin socket, join tokens).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "dev" {
		fmt.Fprintln(os.Stderr, "usage: kevasod dev [--listen 127.0.0.1:8080] [--data PATH]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("dev", flag.ExitOnError)
	home, _ := os.UserHomeDir()
	listen := fs.String("listen", "127.0.0.1:8080", "address to serve the API on (loopback only: no auth yet)")
	data := fs.String("data", filepath.Join(home, ".kevaso", "dev.db"), "SQLite file")
	_ = fs.Parse(os.Args[2:])
	if err := run(*listen, *data); err != nil {
		fmt.Fprintln(os.Stderr, "kevasod:", err)
		os.Exit(1)
	}
}

func run(listen, data string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("dev mode has no authentication: listen on loopback only, not %s", listen)
	}
	if err := os.MkdirAll(filepath.Dir(data), 0o700); err != nil {
		return err
	}
	st, err := store.OpenSQLite(data, 0)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	hs := &http.Server{Addr: listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	fmt.Printf("kevasod dev: API on http://%s, data in %s (Ctrl-C to stop)\n", listen, data)
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
