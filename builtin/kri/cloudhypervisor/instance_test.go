package cloudhypervisor

import (
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// The same guest host key on another host is a new instance, so cloud-init applies this host's
// address. A seed that reuses the key does not replace the guest's host keys.
func TestInstanceIDFollowsTheHostAndAReusedKeyStays(t *testing.T) {
	id := kri.ID{Namespace: "dev", Name: "web", UID: "uid-web"}
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIReportedGuestKey000000000"
	here := MetaData(id, pub, "10.64.0.1")
	there := MetaData(id, pub, "10.64.1.1")
	if here == there {
		t.Fatalf("the same guest key on another host kept the instance id:\n%s", here)
	}
	if MetaData(id, pub, "10.64.0.1") != here {
		t.Fatal("instance id is not stable for one host")
	}
	if !strings.HasPrefix(here, "instance-id: uid-web-") || !strings.Contains(here, "local-hostname: web\n") {
		t.Fatalf("meta-data:\n%s", here)
	}
	if MetaData(id, pub+"x", "10.64.0.1") == here {
		t.Fatal("a new guest key kept the instance id")
	}
	reused := UserData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExecKey00000000000000000", "", pub)
	if !strings.Contains(reused, "ssh_deletekeys: false") || !strings.Contains(reused, "ssh_genkeytypes: []") || strings.Contains(reused, "ssh_keys:") {
		t.Fatalf("a reused key would replace the guest's host keys:\n%s", reused)
	}
	fresh := UserData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExecKey00000000000000000", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n", pub)
	if !strings.Contains(fresh, "ssh_deletekeys: true") || !strings.Contains(fresh, "ssh_genkeytypes: []") || !strings.Contains(fresh, "ssh_keys:") {
		t.Fatalf("a new key was not installed:\n%s", fresh)
	}
}
