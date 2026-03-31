package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

func runExitNode(args []string) {
	fs := flag.NewFlagSet("exit-node", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory (for socket path)")
	outIface := fs.String("out-interface", "", "outbound interface for exit node traffic (enable only)")
	_ = fs.Parse(args)

	// Remaining args after flags are the subcommand and its arguments.
	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "usage: karadul exit-node <enable|use <peer>>")
		os.Exit(1)
	}

	switch remaining[0] {
	case "enable":
		iface := *outIface
		if iface == "" {
			iface = defaultOutInterface()
		}
		if iface == "" {
			fmt.Fprintln(os.Stderr, "error: cannot determine default outbound interface; use --out-interface")
			os.Exit(1)
		}
		body, err := localAPIPost(*dataDir, "/exit-node/enable", map[string]string{
			"out_interface": iface,
		})
		fatalf(err, "enable exit node (is 'karadul up' running?)")
		fmt.Printf("exit node enabled via %s\n", iface)
		_ = body

	case "use":
		if len(remaining) < 2 {
			fmt.Fprintln(os.Stderr, "usage: karadul exit-node use <peer-hostname-or-vip>")
			os.Exit(1)
		}
		peer := remaining[1]
		body, err := localAPIPost(*dataDir, "/exit-node/use", map[string]string{
			"peer": peer,
		})
		fatalf(err, "use exit node (is 'karadul up' running?)")
		fmt.Printf("routing all traffic through exit node %s\n", peer)
		_ = body

	default:
		fmt.Fprintf(os.Stderr, "unknown: %s\n", remaining[0])
		os.Exit(1)
	}
}

// defaultOutInterface tries to determine the default outbound network interface.
func defaultOutInterface() string {
	// Dial a public IP to discover which interface is used.
	conn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.Equal(localAddr.IP) {
				return iface.Name
			}
		}
	}
	return ""
}
