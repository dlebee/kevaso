// Command pluginindex builds and signs a kvo plugin index (ADR 0008). It is a release tool: the
// signing key never leaves the machine that signs.
//
//	go run ./hack/pluginindex keygen DIR                 an ed25519 key in DIR/signing.key (kvoadm's format); prints the public key
//	go run ./hack/pluginindex pubkey KEYFILE             the public key, as kvo takes it (ed25519:…)
//	go run ./hack/pluginindex add INDEX.json --name N --version V --os OS --arch ARCH --kind binary|tar.gz|zip
//	        [--entry PATH] [--url URL] [--description D] [--index-name kevaso] FILE
//	                                                     add (or replace) one build: sha256 and size from FILE;
//	                                                     --url defaults to FILE's path relative to INDEX.json
//	go run ./hack/pluginindex sign KEYFILE INDEX.json    write INDEX.json.sig
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/internal/kvoplugin"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pluginindex:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("keygen|pubkey|add|sign")
	}
	switch args[0] {
	case "keygen":
		if len(args) != 2 {
			return errors.New("keygen DIR")
		}
		priv, _, err := kvoadm.SigningKey(args[1])
		if err != nil {
			return err
		}
		fmt.Println(kvoplugin.FormatKey(priv.Public().(ed25519.PublicKey)))
		return nil
	case "pubkey":
		if len(args) != 2 {
			return errors.New("pubkey KEYFILE")
		}
		priv, err := readKey(args[1])
		if err != nil {
			return err
		}
		fmt.Println(kvoplugin.FormatKey(priv.Public().(ed25519.PublicKey)))
		return nil
	case "sign":
		if len(args) != 3 {
			return errors.New("sign KEYFILE INDEX.json")
		}
		priv, err := readKey(args[1])
		if err != nil {
			return err
		}
		doc, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		if _, err := kvoplugin.Verify(doc, kvoplugin.Sign(priv, doc), priv.Public().(ed25519.PublicKey)); err != nil {
			return err // the index itself is invalid
		}
		return os.WriteFile(args[2]+".sig", kvoplugin.Sign(priv, doc), 0o644)
	case "add":
		return add(args[1:])
	}
	return fmt.Errorf("unknown command %s", args[0])
}

func readKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ed25519 key", path)
	}
	return priv, nil
}

func add(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	name := fs.String("name", "", "plugin name")
	version := fs.String("version", "", "vMAJOR.MINOR.PATCH")
	goos := fs.String("os", "", "darwin, linux, windows")
	arch := fs.String("arch", "", "arm64, amd64")
	kind := fs.String("kind", kvoplugin.KindBinary, "binary, tar.gz or zip")
	entry := fs.String("entry", "", "archives: the program inside")
	rawURL := fs.String("url", "", "where kvo fetches it (default: FILE relative to the index)")
	desc := fs.String("description", "", "one line, for kvo plugin search")
	ixName := fs.String("index-name", kvoplugin.DefaultIndexName, "the index's suggested name, for a new index")
	if len(args) == 0 {
		return errors.New("add INDEX.json [flags] FILE")
	}
	indexPath := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("add INDEX.json [flags] FILE")
	}
	file := fs.Arg(0)
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	h := sha256.New()
	size, err := io.Copy(h, f)
	_ = f.Close()
	if err != nil {
		return err
	}
	u := *rawURL
	if u == "" {
		rel, err := filepath.Rel(filepath.Dir(indexPath), file)
		if err != nil {
			return err
		}
		u = filepath.ToSlash(rel)
	}
	ix := kvoplugin.Index{APIVersion: kvoplugin.APIVersion, Name: *ixName}
	if b, err := os.ReadFile(indexPath); err == nil {
		if err := json.Unmarshal(b, &ix); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ix.Generated = time.Now().UTC().Truncate(time.Second)
	a := kvoplugin.Artifact{OS: *goos, Arch: *arch, URL: u, SHA256: hex.EncodeToString(h.Sum(nil)), Size: size, Kind: *kind, Entry: *entry}
	p := pluginIn(&ix, *name)
	if *desc != "" {
		p.Description = *desc
	}
	v := versionIn(p, *version)
	replaced := false
	for i := range v.Platforms {
		if v.Platforms[i].OS == a.OS && v.Platforms[i].Arch == a.Arch {
			v.Platforms[i], replaced = a, true
		}
	}
	if !replaced {
		v.Platforms = append(v.Platforms, a)
	}
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(indexPath, append(b, '\n'), 0o644)
}

func pluginIn(ix *kvoplugin.Index, name string) *kvoplugin.Plugin {
	if p, ok := ix.Find(name); ok {
		return p
	}
	ix.Plugins = append(ix.Plugins, kvoplugin.Plugin{Name: name})
	return &ix.Plugins[len(ix.Plugins)-1]
}

func versionIn(p *kvoplugin.Plugin, version string) *kvoplugin.Version {
	for i := range p.Versions {
		if p.Versions[i].Version == version {
			return &p.Versions[i]
		}
	}
	p.Versions = append(p.Versions, kvoplugin.Version{Version: version})
	return &p.Versions[len(p.Versions)-1]
}
