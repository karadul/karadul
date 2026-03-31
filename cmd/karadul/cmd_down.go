package main

import (
	"flag"
	"fmt"
	"os"
)

func runDown(args []string) {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "node data directory")
	_ = fs.Parse(args)

	_, err := localAPIPost(*dataDir, "/shutdown", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: node not running or socket not found (%v)\n", err)
		os.Exit(1)
	}
	fmt.Println("node shutting down")
}
