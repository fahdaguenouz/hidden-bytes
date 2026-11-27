package main

import (
	"flag"
	"fmt"
	"os"

	hiddenbytes "hidden-bytes/src/common"
)

func main() {
	encrypt := flag.Bool("encrypt", false, "encrypt a file into a self-extracting runner")
	output := flag.String("output", "", "output file path")
	addSize := flag.Float64("add-size", 0.01, "additional size to add during encryption (MB)")
	delay := flag.Float64("delay", 101.0, "execution delay enforced by the runner (seconds)")
	inspect := flag.Bool("inspect", false, "inspect HBX1 metadata without decrypting")
	decrypt := flag.Bool("decrypt", false, "recover the original file from a runner without executing it")

	flag.Parse()

	if *encrypt {
		if *output == "" {
			fmt.Fprintln(os.Stderr, "evasion: --output is required with --encrypt")
			os.Exit(2)
		}
		if *decrypt || *inspect {
			fmt.Fprintln(os.Stderr, "evasion: --encrypt cannot be combined with --decrypt or --inspect")
			os.Exit(2)
		}

		if _, err := os.Stat(flag.Arg(0)); err != nil {
			fmt.Fprintf(os.Stderr, "evasion: source is not a readable file: %s\n", flag.Arg(0))
			os.Exit(1)
		}

		result, err := BuildRunnerFile(flag.Arg(0), *output, *addSize, *delay)
		if err != nil {
			fmt.Fprintf(os.Stderr, "evasion: error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[OK] Encryption completed.")
		fmt.Printf("[INFO] Input:       %s\n", flag.Arg(0))
		fmt.Printf("[INFO] Runner:      %s\n", *output)
		fmt.Printf("[INFO] Added size:  %g MB\n", *addSize)
		fmt.Printf("[INFO] Delay:       %g second(s)\n", *delay)
		fmt.Printf("[INFO] Runner size: %d bytes\n", result["actual_size"])
		fmt.Println("[INFO] Run the produced file to wait for the delay, decrypt and launch the payload.")
		return
	}

	if *decrypt {
		if *output == "" {
			fmt.Fprintln(os.Stderr, "evasion: --output is required with --decrypt")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "evasion: --decrypt not yet implemented in Go version")
		os.Exit(1)
		return
	}

	if *inspect {
		if flag.Arg(0) == "" {
			fmt.Fprintln(os.Stderr, "evasion: --inspect requires a file argument")
			os.Exit(2)
		}
		header, err := hiddenbytes.ReadContainerHeader(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "evasion: error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%+v\n", header)
		return
	}

	flag.Usage()
	os.Exit(2)
}