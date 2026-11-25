package kvoadm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/internal/admconfig"
)

func authorizedLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

// Only kvoadm's block changes: the operator's own lines stay, before and after it.
func TestReplaceAdminsBlockKeepsOtherLines(t *testing.T) {
	david, ana, own := authorizedLine(t), authorizedLine(t), authorizedLine(t)
	block := AdminsBlock([]admconfig.Admin{{Name: "david", SSHKeys: []string{david + " david@laptop"}}})
	first := ReplaceAdminsBlock(own+" me@box\n", block)
	if !strings.HasPrefix(first, own+" me@box\n"+adminsBegin+"\n") || !strings.Contains(first, david+" kevaso-admin:david\n") {
		t.Fatalf("appended:\n%s", first)
	}
	if ReplaceAdminsBlock(first, block) != first {
		t.Fatal("a second sync changes nothing")
	}
	block2 := AdminsBlock([]admconfig.Admin{{Name: "ana", SSHKeys: []string{ana}}})
	second := ReplaceAdminsBlock(first+"# after\n", block2)
	if strings.Contains(second, david) || !strings.Contains(second, ana+" kevaso-admin:ana") ||
		!strings.Contains(second, own+" me@box") || !strings.HasSuffix(second, "# after\n") {
		t.Fatalf("replaced in place:\n%s", second)
	}
	if strings.Count(second, adminsBegin) != 1 {
		t.Fatal("one block")
	}
	if !authorizes(second, ana) || authorizes(second, david) || !authorizes(second, own) {
		t.Fatal("authorizes reads the file's keys")
	}
	if ReplaceAdminsBlock("no newline at the end", block) != "no newline at the end\n"+block {
		t.Fatal("a last line without a newline")
	}
}

// The sync refuses to write a file that no longer lets in the key kvoadm is connected with.
func TestSyncNeverLocksOutTheConnectingKey(t *testing.T) {
	keyPath, pub := clientKeyFile(t)
	own := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	var wrote []byte
	conn := fakeRunner{run: func(cmd string, stdin []byte) ([]byte, error) {
		if strings.Contains(cmd, "authorized_keys.kevaso") {
			wrote = stdin
			return nil, nil
		}
		return []byte(AdminsBlock([]admconfig.Admin{{Name: "me", SSHKeys: []string{own}}})), nil
	}}
	other := AdminsBlock([]admconfig.Admin{{Name: "ana", SSHKeys: []string{authorizedLine(t)}}})
	if _, err := syncAdminsWith(context.Background(), conn, InitOptions{User: "root", SSHKey: keyPath}, other, false); err == nil || !strings.Contains(err.Error(), "add yourself") {
		t.Fatalf("lock-out refused: %v", err)
	}
	if wrote != nil {
		t.Fatal("nothing written")
	}
	mine := AdminsBlock([]admconfig.Admin{{Name: "me", SSHKeys: []string{own}}, {Name: "ana", SSHKeys: []string{authorizedLine(t)}}})
	changed, err := syncAdminsWith(context.Background(), conn, InitOptions{User: "root", SSHKey: keyPath}, mine, false)
	if err != nil || !changed || !bytes.Contains(wrote, []byte("kevaso-admin:ana")) {
		t.Fatalf("written: %v %v\n%s", changed, err, wrote)
	}
}

func TestAdminsCommand(t *testing.T) {
	root := t.TempDir()
	t.Setenv(admconfig.EnvHome, root)
	t.Setenv(admconfig.EnvCluster, "")
	if err := admconfig.New(root, "lab").Save(); err != nil {
		t.Fatal(err)
	}
	keyPath, _ := clientKeyFile(t)
	pubFile := keyPath + ".pub"
	if err := os.WriteFile(pubFile, []byte(publicKeyOf(keyPath)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	ctx := context.Background()
	if err := adminsCmd(ctx, []string{"add", "ana", pubFile}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if err := adminsCmd(ctx, []string{"add", "eve", keyPath}, nil, &out); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("a private key file: %v", err)
	}
	out.Reset()
	if err := adminsCmd(ctx, []string{"--cluster", "lab"}, nil, &out); err != nil || !strings.Contains(out.String(), "ana") || !strings.Contains(out.String(), "SHA256:") {
		t.Fatalf("list: %v\n%s", err, out.String())
	}
	if err := adminsCmd(ctx, []string{"remove", "ana"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if err := adminsCmd(ctx, []string{"remove", "ana"}, nil, &out); err == nil {
		t.Fatal("removing someone who isn't there")
	}
}

type fakeRunner struct {
	run func(cmd string, stdin []byte) ([]byte, error)
}

func (f fakeRunner) Run(_ context.Context, cmd string, stdin []byte) ([]byte, error) {
	return f.run(cmd, stdin)
}
