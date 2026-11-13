// Command kvtsh runs a shell script as root on a metal test machine, over SSH with the pinned
// host key, reading the machine from the same variables as the metal suite (KEVASO_METAL_*, or
// with -2 KEVASO_METAL2_*):
//
//	go run ./testbed/remote/cmd/kvtsh 'journalctl -u kevasod -n 50 --no-pager'
//	go run ./testbed/remote/cmd/kvtsh -2 'docker ps'
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"kevaso.com/core/testbed/remote"
)

func main() {
	second := flag.Bool("2", false, "the second machine (KEVASO_METAL2_*)")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: kvtsh [-2] 'SCRIPT'")
		os.Exit(2)
	}
	prefix := "KEVASO_METAL"
	if *second {
		prefix = remote.SecondPrefix
	}
	cfg, err := remote.FromEnvPrefix(os.Getenv, prefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kvtsh:", err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	d := remote.New(cfg)
	defer func() { _ = d.Close() }()
	out, err := d.Run(ctx, flag.Arg(0), nil)
	fmt.Print(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kvtsh:", err)
		os.Exit(1)
	}
}
