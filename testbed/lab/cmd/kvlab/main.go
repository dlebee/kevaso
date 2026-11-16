// Command kvlab builds and removes a worktree lab: three nested node VMs on the lab host.
//
//	kvlab up --name smoke
//	kvlab down --name smoke
//	kvlab list
//
// The host comes from LAB_HOST and LAB_SSH_KEY (defaults: ubuntu@54.39.243.98 and
// ~/.ssh/kevaso-testbed_ed25519). LAB_HOSTKEY, when set, is the host's ED25519 fingerprint;
// otherwise it is read from the user's known_hosts, and a host that isn't there is refused.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "up":
		err = cmdUp(os.Args[2:])
	case "down":
		err = cmdDown(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "kvlab: %s\n", scrub(err.Error()))
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `kvlab up --name NAME [--recreate]
kvlab down --name NAME
kvlab list

LAB_HOST, LAB_SSH_KEY and LAB_HOSTKEY choose the lab host.
`)
}

func nameFlag(args []string, set *flag.FlagSet) string {
	name := set.String("name", "", "lab name (a lowercase DNS label, at most 12 characters)")
	set.SetOutput(os.Stderr)
	if err := set.Parse(args); err != nil {
		os.Exit(2)
	}
	if *name == "" && set.NArg() == 1 {
		*name = set.Arg(0)
	}
	return *name
}

// scrub keeps a private key or a recovery key out of an error that included command output.
func scrub(s string) string {
	var b strings.Builder
	hide := false
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "BEGIN OPENSSH PRIVATE KEY") || strings.Contains(line, "BEGIN PRIVATE KEY") {
			hide = true
		}
		if hide || strings.Contains(line, "KVR1-") {
			b.WriteString("(secret redacted)\n")
		} else {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		if hide && (strings.Contains(line, "END OPENSSH PRIVATE KEY") || strings.Contains(line, "END PRIVATE KEY")) {
			hide = false
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
