package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/karadul/karadul/internal/crypto"
)

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fs.String("dir", defaultDataDir(), "directory to save keys")
	_ = fs.Parse(args)

	kp, err := crypto.GenerateKeyPair()
	fatalf(err, "generate key pair")

	if err := crypto.SaveKeyPair(kp, *dir); err != nil {
		fatalf(err, "save key pair")
	}
	fmt.Printf("public key:  %s\n", kp.Public.String())
	fmt.Printf("private key: saved to %s/private.key\n", *dir)
}

func runAuth(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: karadul auth create-key [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "create-key":
		runCreateAuthKey(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown auth subcommand: %s\n", args[0])
		os.Exit(1)
	}
}
