// Command where prints test/WHERE.md: which tests exist under each build tag and where they run.
// `make where` writes it; test/where's test fails when the checked-in copy is stale.
package main

import (
	"fmt"
	"os"

	"kevaso.com/core/test/where"
)

func main() {
	out, err := where.Generate(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "where:", err)
		os.Exit(1)
	}
	fmt.Print(out)
}
