// Package ocienv is kevaso-oci, the thin OCI runtime that gives a container silo its env secrets
// without the container engine ever holding their values (ADR 0009 addendum, "Variables").
//
// The engine is told to start the container with this runtime (docker: `--runtime kevaso-oci`,
// registered in daemon.json; the path is ShimPath, a link to kevasod, which runs Main when it's
// called by that name). The engine's shim calls it exactly as it would call runc. For `create`
// (and `run`) it reads the bundle's config.json, finds the annotation Annotation (the silo's short
// id, never a value), reads that silo's env file from the host's secrets tmpfs, sets those
// variables in process.env, writes the config back and execs the real runtime with the same
// arguments and environment. Every other action, and any container without the annotation, goes
// straight to the real runtime: ordinary containers on the host are unaffected. Nothing of it runs
// in the container, and it implements nothing of the OCI runtime itself.
//
// It fails closed: a container that has the annotation and whose env file can't be read (missing,
// not root's, a link, a bad line), or whose bundle isn't in memory, isn't started; the message
// goes to stderr and the runtime's log, which the engine shows. It never writes a value anywhere
// but the bundle's config.json, and never logs one.
package ocienv

import (
	"fmt"
	"strings"
)

// Invocation is what this runtime needs from a command line: the action and, for create and run,
// the bundle, the config file's name and the container id. Everything else is passed on untouched.
type Invocation struct {
	Action    string // create, run, start, exec, … ("" when there is none: --version, --help)
	Bundle    string // --bundle / -b ("" means the current folder, as runc takes it)
	Config    string // crun's --config / -f (a name in the bundle; "" is config.json)
	ID        string // the container id (the action's first argument)
	Log       string // the global --log: where the engine reads the runtime's errors
	LogFormat string // the global --log-format (json | text)
}

// The runtime's global flags that take a value as the next argument (runc, crun, youki). The
// others are switches. A flag written --name=value takes its value with it.
var globalValueFlags = map[string]bool{
	"root": true, "log": true, "log-format": true, "log-level": true, "criu": true, "rootless": true, "cgroup-manager": true,
}

// The flags of create and run that take a value (runc's and crun's).
var createValueFlags = map[string]bool{
	"bundle": true, "b": true, "pid-file": true, "console-socket": true, "pidfd-socket": true, "preserve-fds": true, "config": true, "f": true,
}

// actions are the runtime commands (runc's and crun's); an action not here is passed through.
var actions = map[string]bool{
	"checkpoint": true, "create": true, "delete": true, "events": true, "exec": true, "features": true, "init": true,
	"kill": true, "list": true, "pause": true, "ps": true, "restore": true, "resume": true, "run": true, "spec": true,
	"start": true, "state": true, "update": true, "help": true, "mounts": true,
}

// flag splits -x, --name and --name=value.
func flag(a string) (name, value string, hasValue bool) {
	n := strings.TrimLeft(a, "-")
	if i := strings.IndexByte(n, '='); i >= 0 {
		return n[:i], n[i+1:], true
	}
	return n, "", false
}

// Parse reads a runtime command line (without argv[0]): global flags, the action, its flags, the
// container id. It's strict only where it matters: a command line that looks like a create (it
// names a bundle) but whose action it can't tell is an error, never a pass-through that would
// start a container without its variables.
func Parse(args []string) (Invocation, error) {
	var inv Invocation
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		name, v, has := flag(a)
		if globalValueFlags[name] && !has {
			if i+1 >= len(args) {
				return inv, fmt.Errorf("the global flag %s has no value", a)
			}
			i++
			v = args[i]
		}
		switch name {
		case "log":
			inv.Log = v
		case "log-format":
			inv.LogFormat = v
		}
	}
	if i < len(args) && args[i] == "--" {
		i++
	}
	if i >= len(args) {
		return inv, nil // runc --version, crun --help
	}
	inv.Action = args[i]
	if !actions[inv.Action] {
		for _, a := range args {
			if n, _, _ := flag(a); strings.HasPrefix(a, "-") && (n == "bundle" || n == "b") {
				return inv, fmt.Errorf("can't tell the action of this command line (%q comes before the bundle)", inv.Action)
			}
		}
		return inv, nil
	}
	if inv.Action != "create" && inv.Action != "run" {
		return inv, nil
	}
	for i++; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		name, v, has := flag(a)
		if createValueFlags[name] && !has {
			if i+1 >= len(args) {
				return inv, fmt.Errorf("%s has no value", a)
			}
			i++
			v = args[i]
		}
		switch name {
		case "bundle", "b":
			inv.Bundle = v
		case "config", "f":
			inv.Config = v
		}
	}
	if i < len(args) {
		inv.ID = args[i]
	}
	if inv.ID == "" {
		return inv, fmt.Errorf("%s without a container id", inv.Action)
	}
	return inv, nil
}
