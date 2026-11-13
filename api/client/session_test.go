package client

import (
	"bytes"
	"strings"
	"testing"
)

func TestResizeFrame(t *testing.T) {
	var b bytes.Buffer
	if err := WriteFrame(&b, FrameResize, ResizePayload(50, 132)); err != nil {
		t.Fatal(err)
	}
	typ, p, err := ReadFrame(&b)
	if err != nil || typ != FrameResize {
		t.Fatal(typ, err)
	}
	if r, c, ok := ParseResize(p); !ok || r != 50 || c != 132 {
		t.Fatalf("%d %d %v", r, c, ok)
	}
	for _, bad := range [][]byte{nil, {0, 1, 0}, ResizePayload(0, 80), ResizePayload(24, 0)} {
		if _, _, ok := ParseResize(bad); ok {
			t.Errorf("%v: want not ok", bad)
		}
	}
}

// Output and the exit code come back in order; stdin larger than a frame is split.
func TestFramesRoundTrip(t *testing.T) {
	var b bytes.Buffer
	var s Session
	s.s = nopCloser{&b}
	big := strings.Repeat("y", MaxFrame+10)
	if _, err := s.Write([]byte(big)); err != nil {
		t.Fatal(err)
	}
	_ = s.Resize(10, 20)
	_ = s.CloseStdin()
	var got []byte
	var kinds []byte
	for {
		typ, p, err := ReadFrame(&b)
		if err != nil {
			break
		}
		kinds = append(kinds, typ)
		if typ == FrameStdin {
			got = append(got, p...)
		}
	}
	if string(got) != big || !bytes.Equal(kinds, []byte{FrameStdin, FrameStdin, FrameResize, FrameStdinClose}) {
		t.Fatalf("frames %v, %d bytes", kinds, len(got))
	}
	if err := WriteFrame(&b, FrameStdout, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("a frame over the limit")
	}
	b.Reset()
	_ = WriteFrame(&b, FrameStdout, []byte("out"))
	_ = WriteFrame(&b, FrameStderr, []byte("err"))
	_ = WriteFrame(&b, FrameExit, []byte{0xff, 0xff, 0xff, 0xfe})
	var o, e bytes.Buffer
	code, err := ReadOutput(&b, &o, &e)
	if err != nil || code != -2 || o.String() != "out" || e.String() != "err" {
		t.Fatalf("%d %v %q %q", code, err, o.String(), e.String())
	}
}

type nopCloser struct{ *bytes.Buffer }

func (nopCloser) Close() error { return nil }
