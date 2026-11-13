// Command kvo-whoami is the example kvo plugin: who you are in the current context, and what you
// can do in its namespace. Install it with `kvo plugin install whoami`, run it with `kvo whoami`.
// kvoctx.go is the part every plugin needs; the rest is this plugin's own.
package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// version is set at build time: go build -ldflags "-X main.version=v0.2.0".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kvo-whoami:", err)
		os.Exit(1)
	}
}

func run() error {
	ns := ""
	for i := 1; i < len(os.Args); i++ {
		switch a := os.Args[i]; {
		case (a == "-n" || a == "--namespace") && i+1 < len(os.Args):
			i++
			ns = os.Args[i]
		case a == "--version":
			fmt.Println(version)
			return nil
		case a == "-h" || a == "--help":
			fmt.Println("kvo whoami [-n NAMESPACE]: who you are in the current context, and what you can do there")
			return nil
		default:
			return fmt.Errorf("unknown argument %s", a)
		}
	}
	s, err := fromKvo()
	if err != nil {
		return err
	}
	if ns == "" {
		ns = s.Namespace
	}
	var me struct {
		Type, Name string
		Groups     []string
	}
	if err := s.get("/auth/whoami", &me); err != nil {
		return err
	}
	ctx := s.Context
	if ctx == "" {
		ctx = "(none)"
	}
	fmt.Printf("%s %s\n", me.Type, me.Name)
	if len(me.Groups) > 0 {
		fmt.Printf("groups:    %s\n", strings.Join(me.Groups, ", "))
	}
	fmt.Printf("context:   %s\nserver:    %s\nnamespace: %s\n", ctx, s.Server, ns)
	if t, err := s.token(); err == nil && !t.ExpiresAt.IsZero() {
		fmt.Printf("token:     short-lived, %s left\n", time.Until(t.ExpiresAt).Round(time.Second))
	}

	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CAN YOU\tSILOS\tSECRETS")
	for _, verb := range []string{"list", "create", "delete"} {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", verb, s.canI(verb, "silos", ns), s.canI(verb, "secrets", ns))
	}
	_, _ = fmt.Fprintf(tw, "exec into\t%s\t\n", s.canI("create", "silos/exec", ns))
	return tw.Flush()
}

func (s *session) canI(verb, resource, ns string) string {
	var ans struct{ Allowed bool }
	q := url.Values{"verb": {verb}, "resource": {resource}, "namespace": {ns}}
	if err := s.get("/auth/can-i?"+q.Encode(), &ans); err != nil {
		return "?"
	}
	if ans.Allowed {
		return "yes"
	}
	return "no"
}
