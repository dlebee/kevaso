// Command kvtcs is the plugin binary TestLabClusterSecret installs on a lab worker.
// The unit starts it as "kevaso-plugin-kvtcs node --socket …". It does not open that
// socket and it does not read its credential: it stays up until systemd stops it, so
// a restart shows up as a new start time and a new main process.
package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
}
