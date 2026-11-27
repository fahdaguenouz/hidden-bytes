// Evasion encrypts a target binary and wraps it in a self-extracting
// Windows runner with file-size inflation and an execution delay.
//
// Usage:
//
//	evasion --encrypt target.exe --output evaded.exe --add-size 101 --delay 101
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Evasion Program Usage:")
		fmt.Fprintln(os.Stderr, "  --encrypt <target-binary>    Encrypt the target binary.")
		fmt.Fprintln(os.Stderr, "  --output  <output-binary>    Specify the output file path.")
		fmt.Fprintln(os.Stderr, "  --add-size <size-in-mb>      Increase the binary size (e.g., 101 MB).")
		fmt.Fprintln(os.Stderr, "  --delay   <seconds>          Execution delay in seconds (default: 101).")
	}

	encrypt := flag.String("encrypt", "", "target binary to encrypt")
	output := flag.String("output", "", "output file path")
	addSize := flag.Float64("add-size", 0, "padding to add in MB (e.g., 101)")
	delay := flag.Float64("delay", 101, "execution delay in seconds")
	flag.Parse()

	if *encrypt == "" || *output == "" {
		flag.Usage()
		os.Exit(2)
	}

	if err := encryptAndBuild(*encrypt, *output, *addSize, *delay); err != nil {
		fmt.Fprintf(os.Stderr, "evasion: %v\n", err)
		os.Exit(1)
	}
}
