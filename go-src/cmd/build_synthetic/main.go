// Command build_synthetic produces a tiny trivy-db fixture used by
// pytrivydb's Python test suite. It is invoked by `just regen-fixture`
// (or automatically by the pytest session-scoped autouse fixture if
// the on-disk fixture is missing).
package main

import (
	"fmt"
	"os"

	"github.com/drape-io/pytrivydb/go-src/pkg/writer"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <fixture-dir>\n", os.Args[0])
		os.Exit(2)
	}
	dir := os.Args[1]
	if err := writer.WriteFixture(dir, writer.SupportedSchemaVersion); err != nil {
		fmt.Fprintln(os.Stderr, "fixture build failed:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote fixture: %s/metadata.json + %s/trivy.db\n", dir, dir)
}
