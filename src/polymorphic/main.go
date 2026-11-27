package main

import (
	"flag"
	"fmt"
	"os"

	hiddenbytes "hidden-bytes/src/common"
)

func main() {
	generate := flag.String("generate", "", "path of the generated polymorphic program")
	payload := flag.String("payload", "", "path to the payload file to embed")

	flag.Parse()

	if *generate == "" || *payload == "" {
		fmt.Fprintln(os.Stderr, "Usage: polymorphic --generate <output-binary> --payload <payload-file>")
		os.Exit(2)
	}

	payloadData, err := os.ReadFile(*payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "polymorphic: error: payload file does not exist: %s\n", *payload)
		os.Exit(1)
	}

	if len(payloadData) == 0 {
		fmt.Fprintln(os.Stderr, "polymorphic: error: payload must not be empty")
		os.Exit(1)
	}

	gen := NewPolymorphicGenerator(payloadData)

	if err := os.WriteFile(*generate, []byte(gen.GenerateSourceTemplate()), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "polymorphic: error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[OK] Generated polymorphic program: %s\n", *generate)
	fmt.Println("[INFO] The payload is encrypted inside the generated program.")
	fmt.Println("[INFO] Every run rewrites the program's own source, so its hash changes while its behaviour stays the same.")

	_ = hiddenbytes.Base64Encode([]byte{})
}