package e2e

import (
	"fmt"
	"strconv"
)

// labProbeScript is a python3 program run inside a silo. It GETs 127.0.0.1:port
// and reads until want appears, the server closes, or a short deadline. One
// recv can return only the headers: the echo server writes those, then the body,
// and they can arrive as two segments. The whole connection is tried a few times
// before the program gives up. want is a silo name (letters, digits, hyphen).
func labProbeScript(port int, want string) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("port %d: want a TCP port", port)
	}
	for _, r := range want {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return "", fmt.Errorf("probe want %q: want a silo name", want)
		}
	}
	if want == "" {
		return "", fmt.Errorf("probe want: empty")
	}
	return fmt.Sprintf(`import socket, time, sys
want = %s
port = %d
last = b""
for _ in range(3):
    try:
        s = socket.create_connection(("127.0.0.1", port), 2)
    except OSError as e:
        last = str(e).encode()
        time.sleep(0.2)
        continue
    try:
        s.settimeout(0.2)
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        buf = b""
        end = time.monotonic() + 2
        while want.encode() not in buf and time.monotonic() < end:
            try:
                chunk = s.recv(400)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
        last = buf
        if want.encode() in buf:
            break
    finally:
        s.close()
sys.stdout.buffer.write(last)
if want.encode() not in last:
    sys.exit(1)
`, strconv.Quote(want), port), nil
}

// labReadUntil is the same read as labProbeScript, for a socket that is already
// connected (the TLS probe). It stops at want, at EOF, or at a short deadline,
// whichever comes first.
func labReadUntil(want string, seconds int) string {
	return fmt.Sprintf(`buf = b""
end = time.monotonic() + %d
while %s not in buf and time.monotonic() < end:
    try:
        chunk = tls.recv(180)
    except socket.timeout:
        continue
    if not chunk:
        break
    buf += chunk
sys.stdout.buffer.write(buf)
`, seconds, "b"+strconv.Quote(want))
}
