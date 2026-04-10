package main

import (
	"flag"
	"fmt"
	"os"
)

const version = "0.1.0"

// parseFlags handles CLI flags before the main run loop.
// It returns true if the program should continue after flag parsing.
func parseFlags() bool {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")
		showHelp    = flag.Bool("help", false, "print usage and exit")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("vaultwatch v%s\n", version)
		return false
	}

	if *showHelp {
		fmt.Fprintf(os.Stdout, "Usage: vaultwatch [options]\n\n")
		fmt.Fprintf(os.Stdout, "Options:\n")
		flag.PrintDefaults()
		return false
	}

	return true
}
