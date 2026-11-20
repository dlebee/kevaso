package kvoadm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"text/tabwriter"
	"time"

	"kevaso.com/core/internal/agent"
)

const keptUsage = "usage: kvoadm host kept [USER@]ADDRESS --ssh-key PATH [--host-key SHA256:…] [--ssh-port N] [--data DIR] [--remove NAMESPACE/NAME/UID [--yes]]"

// KeptOptions are kvoadm host kept's flags.
type KeptOptions struct {
	TrustOptions
	Remove string // NAMESPACE/NAME/UID (the UID's first 8 characters are enough)
}

// hostKept: kvoadm host kept [USER@]ADDRESS (K-068 b). It lists the silo copies a worker keeps
// though its control plane doesn't know them (a delete it never saw, a restore that forgot them):
// each runs, or is stopped, with its disk and volumes. With --remove, once a person confirms, the
// worker removes that copy, disk and volumes, as for a delete it saw: the confirmation is the
// proof (the worker removes nothing on its own without a delete it saw).
func hostKept(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	var remove string
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--remove" && i+1 < len(args) {
			remove = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	t, err := parseTrust(rest)
	if err != nil {
		return fmt.Errorf("%v\n%s", strings.ReplaceAll(err.Error(), trustUsage, ""), keptUsage)
	}
	in := bufio.NewReader(stdin)
	conn, _, err := dialHost(ctx, t.InitOptions, in, stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return runKept(ctx, conn, KeptOptions{TrustOptions: t, Remove: remove}, in, out, time.Second)
}

// KeptListScript prints the worker's list of kept copies ("[]" if it has none yet).
func KeptListScript(data string) string {
	f := path.Join(data, agent.KeptFile)
	return "cat " + shQuote(f) + " 2>/dev/null || echo '[]'"
}

// KeptRemoveScript asks the worker to remove the kept copy uid (a file named by it).
func KeptRemoveScript(data, uid string) string {
	d := path.Join(data, agent.KeptRemoveDir)
	return "set -e; install -d -m 0700 " + shQuote(d) + "; echo kvoadm > " + shQuote(path.Join(d, uid)) + "; echo asked"
}

// KeptRemovedScript reads whether the worker removed uid (it writes "removed" only then).
func KeptRemovedScript(data, uid string) string {
	return "cat " + shQuote(path.Join(data, agent.KeptRemovedDir, uid)) + " 2>/dev/null || true"
}

func readKept(ctx context.Context, h hostRunner, data string) ([]agent.KeptEntry, error) {
	b, err := h.Run(ctx, KeptListScript(data), nil)
	if err != nil {
		return nil, err
	}
	var l []agent.KeptEntry
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", path.Join(data, agent.KeptFile), err)
	}
	return l, nil
}

func runKept(ctx context.Context, h hostRunner, o KeptOptions, in *bufio.Reader, out io.Writer, every time.Duration) error {
	l, err := readKept(ctx, h, o.Data)
	if err != nil {
		return err
	}
	if o.Remove == "" {
		if len(l) == 0 {
			_, _ = fmt.Fprintf(out, "%s keeps no copy the control plane doesn't know\n", o.Address)
			return nil
		}
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "SILO\tUID\tRUNTIME\tWHAT")
		for _, e := range l {
			_, _ = fmt.Fprintf(tw, "%s/%s\t%s\t%s\t%s\n", e.Namespace, e.Name, e.UID, e.Runtime, e.What)
		}
		return tw.Flush()
	}
	parts := strings.Split(o.Remove, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || len(parts[2]) < 8 {
		return fmt.Errorf("--remove %q: NAMESPACE/NAME/UID (at least the UID's first 8 characters, as kvoadm host kept lists it)", o.Remove)
	}
	var match []agent.KeptEntry
	for _, e := range l {
		if e.Namespace == parts[0] && e.Name == parts[1] && strings.HasPrefix(e.UID, parts[2]) {
			match = append(match, e)
		}
	}
	switch len(match) {
	case 0:
		return fmt.Errorf("%s keeps no copy %s: nothing removed (kvoadm host kept %s lists what it keeps)", o.Address, o.Remove, o.Address)
	case 1:
	default:
		return fmt.Errorf("%s matches %d kept copies: give more of the UID", o.Remove, len(match))
	}
	e := match[0]
	held := "The control plane doesn't know it, so nothing else holds this data."
	if strings.Contains(e.What, "stopped:") {
		held = "The control plane still has this silo: this host keeps a stopped copy, and removing it deletes only what is on this host."
	}
	removing := fmt.Sprintf("Removing it deletes the copy, its disk and its volumes on %s, for good.", o.Address)
	if e.Shared != "" {
		removing = fmt.Sprintf("Removing it deletes only this host's copy; the volumes on %s stay.", e.Shared)
	}
	_, _ = fmt.Fprintf(out, "%s keeps %s/%s (uid %s, %s): %s.\n%s %s\n",
		o.Address, e.Namespace, e.Name, e.UID, e.Runtime, e.What, removing, held)
	if !o.Yes {
		_, _ = fmt.Fprintf(out, "Type the silo's name (%s/%s) to remove it: ", e.Namespace, e.Name)
		line, _ := readLine(in)
		if strings.TrimSpace(line) != e.Namespace+"/"+e.Name {
			return errors.New("not confirmed: nothing was removed")
		}
	}
	if b, err := h.Run(ctx, KeptRemoveScript(o.Data, e.UID), nil); err != nil || strings.TrimSpace(lastLineString(b)) != "asked" {
		return fmt.Errorf("asking %s to remove it: %v %s", o.Address, err, strings.TrimSpace(string(b)))
	}
	for i := 0; i < 60; i++ {
		if b, err := h.Run(ctx, KeptRemovedScript(o.Data, e.UID), nil); err == nil && strings.TrimSpace(string(b)) == "removed" {
			_, _ = fmt.Fprintf(out, "→ %s/%s (uid %s) removed from %s\n", e.Namespace, e.Name, e.UID, o.Address)
			return nil
		}
		l, err := readKept(ctx, h, o.Data)
		if err == nil {
			gone := true
			for _, x := range l {
				if x.UID == e.UID {
					gone = false
				}
			}
			if gone {
				return fmt.Errorf("%s/%s (uid %s) left the list of copies %s keeps, and it was not removed", e.Namespace, e.Name, e.UID, o.Address)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
	return fmt.Errorf("asked %s to remove %s/%s; it is still listed after a minute: see kevasod's log there (journalctl -u kevasod)", o.Address, e.Namespace, e.Name)
}
