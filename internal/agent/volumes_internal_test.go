package agent

import (
	"context"
	"os"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/hostexec"
)

// fakeHost answers commands by their first words; it records every command.
type fakeHost struct {
	codes map[string]int    // "blkid" → exit code
	out   map[string]string // "blkid" → stdout
	ran   []string
}

func (f *fakeHost) Run(_ context.Context, c hostexec.Cmd) (int, error) {
	line := c.Name + " " + strings.Join(c.Args, " ")
	f.ran = append(f.ran, line)
	if c.Stdout != nil {
		_, _ = c.Stdout.Write([]byte(f.out[c.Name]))
	}
	return f.codes[c.Name], nil
}
func (f *fakeHost) WriteFile(string, []byte, os.FileMode) error { return nil }
func (f *fakeHost) ReadFile(string) ([]byte, error)             { return nil, os.ErrNotExist }
func (f *fakeHost) RemoveAll(string) error                      { return nil }
func (f *fakeHost) Glob(string) ([]string, error)               { return nil, nil }

func (f *fakeHost) did(prefix string) bool {
	for _, r := range f.ran {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func TestMountFormatsOnlyAnEmptyVolume(t *testing.T) {
	const dev, dir = "/dev/disk/by-id/scsi-0Linode_Volume_v", "/var/lib/kevaso/volumes/u/data"
	for _, tc := range []struct {
		name       string
		blkidCode  int
		blkidOut   string
		wantFormat bool
		wantErr    string
	}{
		{"empty: formatted, then mounted", 2, "", true, ""},
		{"ext4 already: mounted as it is", 0, "ext4\n", false, ""},
		{"xfs from elsewhere: mounted as it is", 0, "xfs\n", false, ""},
		{"blkid fails otherwise: left alone", 4, "", false, "not formatting"},
		{"something unnamed: left alone", 0, "\n", false, "not formatting"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": tc.blkidCode}, out: map[string]string{"blkid": tc.blkidOut}}
			a := &Agent{Host: h}
			err := a.mount(context.Background(), dev, dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err %v, want %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if got := h.did("mkfs"); got != tc.wantFormat {
				t.Fatalf("formatted: %v, want %v (%v)", got, tc.wantFormat, h.ran)
			}
			if tc.wantErr == "" && !h.did("mount -o noatime "+dev+" "+dir) {
				t.Fatalf("not mounted: %v", h.ran)
			}
		})
	}
	// Already mounted: nothing else happens. Not there yet: wait.
	h := &fakeHost{codes: map[string]int{"mountpoint": 0}}
	if err := (&Agent{Host: h}).mount(context.Background(), dev, dir); err != nil || len(h.ran) != 1 {
		t.Fatalf("already mounted: %v %v", err, h.ran)
	}
	h = &fakeHost{codes: map[string]int{"mountpoint": 1, "test": 1}}
	if err := (&Agent{Host: h}).mount(context.Background(), dev, dir); err != errNoDevice {
		t.Fatalf("no device yet: %v", err)
	}
}
