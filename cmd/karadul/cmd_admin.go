package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func runAdmin(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, "usage: karadul admin <subcommand>\n\nSubcommands:\n"+
			"  nodes                    List all nodes\n"+
			"  nodes approve <id>       Approve a pending node\n"+
			"  nodes delete  <id>       Delete a node\n"+
			"  auth-keys                List auth keys\n"+
			"  auth-keys create         Create a new auth key\n"+
			"  auth-keys delete <id>    Revoke an auth key\n"+
			"  acl get                  Print current ACL policy\n"+
			"  acl set [file]           Upload ACL policy from file or stdin\n")
		os.Exit(1)
	}

	switch args[0] {
	case "nodes":
		runAdminNodes(args[1:])
	case "auth-keys":
		runAdminAuthKeys(args[1:])
	case "acl":
		runAdminACL(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown admin subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func runAdminNodes(args []string) {
	fs := flag.NewFlagSet("admin-nodes", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "coordinator server URL")
	_ = fs.Parse(args)

	sub := ""
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
	}

	switch sub {
	case "", "list":
		body := adminDo("GET", *server+"/api/v1/admin/nodes", nil)
		var nodes []map[string]interface{}
		if err := json.Unmarshal(body, &nodes); err != nil {
			fmt.Println(string(body))
			return
		}
		if len(nodes) == 0 {
			fmt.Println("no nodes")
			return
		}
		fmt.Printf("%-20s %-15s %-10s %-10s\n", "HOSTNAME", "VIP", "STATUS", "ID")
		for _, n := range nodes {
			fmt.Printf("%-20s %-15s %-10s %-10s\n",
				strOrDash(n["hostname"]),
				strOrDash(n["virtualIP"]),
				strOrDash(n["status"]),
				shortID(strOrDash(n["id"])),
			)
		}
	case "approve":
		if fs.NArg() < 2 {
			fatalf(fmt.Errorf("node id required"), "admin nodes approve")
		}
		id := fs.Arg(1)
		adminDo("POST", *server+"/api/v1/admin/nodes/"+id+"/approve", nil)
		fmt.Printf("node %s approved\n", id)
	case "delete":
		if fs.NArg() < 2 {
			fatalf(fmt.Errorf("node id required"), "admin nodes delete")
		}
		id := fs.Arg(1)
		adminDoStatus("DELETE", *server+"/api/v1/admin/nodes/"+id, nil, http.StatusNoContent)
		fmt.Printf("node %s deleted\n", id)
	default:
		fmt.Fprintf(os.Stderr, "unknown nodes subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func runAdminAuthKeys(args []string) {
	fs := flag.NewFlagSet("admin-auth-keys", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "coordinator server URL")
	ephemeral := fs.Bool("ephemeral", false, "create single-use key")
	expiry := fs.String("expiry", "24h", "key expiry duration (empty = no expiry)")
	_ = fs.Parse(args)

	sub := ""
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
	}

	switch sub {
	case "", "list":
		body := adminDo("GET", *server+"/api/v1/admin/auth-keys", nil)
		var keys []map[string]interface{}
		if err := json.Unmarshal(body, &keys); err != nil {
			fmt.Println(string(body))
			return
		}
		if len(keys) == 0 {
			fmt.Println("no auth keys")
			return
		}
		fmt.Printf("%-20s %-10s %-10s %s\n", "ID", "EPHEMERAL", "USED", "EXPIRES")
		for _, k := range keys {
			fmt.Printf("%-20s %-10v %-10v %s\n",
				strOrDash(k["id"]),
				k["ephemeral"],
				k["used"],
				strOrDash(k["expiresAt"]),
			)
		}
	case "create":
		payload, _ := json.Marshal(map[string]interface{}{
			"ephemeral": *ephemeral,
			"expiry":    *expiry,
		})
		body := adminDoStatus("POST", *server+"/api/v1/admin/auth-keys", payload, http.StatusCreated)
		var k map[string]interface{}
		if err := json.Unmarshal(body, &k); err != nil {
			fmt.Println(string(body))
			return
		}
		fmt.Printf("auth-key: %s\n", strOrDash(k["key"]))
		fmt.Printf("id:       %s\n", strOrDash(k["id"]))
		fmt.Printf("ephemeral: %v\n", k["ephemeral"])
		if exp, ok := k["expiresAt"]; ok && exp != nil && exp != "" {
			fmt.Printf("expires:  %v\n", exp)
		}
	case "delete":
		if fs.NArg() < 2 {
			fatalf(fmt.Errorf("key id required"), "admin auth-keys delete")
		}
		id := fs.Arg(1)
		adminDoStatus("DELETE", *server+"/api/v1/admin/auth-keys/"+id, nil, http.StatusNoContent)
		fmt.Printf("auth key %s revoked\n", id)
	default:
		fmt.Fprintf(os.Stderr, "unknown auth-keys subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func runAdminACL(args []string) {
	fs := flag.NewFlagSet("admin-acl", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "coordinator server URL")
	_ = fs.Parse(args)

	sub := ""
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
	}

	switch sub {
	case "", "get":
		body := adminDo("GET", *server+"/api/v1/admin/acl", nil)
		var v interface{}
		_ = json.Unmarshal(body, &v)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	case "set":
		// Read ACL policy from a file argument or stdin.
		var payload []byte
		var err error
		if fs.NArg() >= 2 {
			payload, err = os.ReadFile(fs.Arg(1))
			fatalf(err, "read acl file")
		} else {
			payload, err = io.ReadAll(os.Stdin)
			fatalf(err, "read acl from stdin")
		}
		adminDoStatus("PUT", *server+"/api/v1/admin/acl", payload, http.StatusOK)
		fmt.Println("ACL policy updated")
	default:
		fmt.Fprintf(os.Stderr, "unknown acl subcommand: %s\n", sub)
		os.Exit(1)
	}
}

// adminDo calls a coordinator admin endpoint and returns the response body.
// Exits on non-2xx status.
func adminDo(method, url string, payload []byte) []byte {
	return adminDoStatus(method, url, payload, http.StatusOK)
}

// adminDoStatus is like adminDo but expects a specific status code.
func adminDoStatus(method, url string, payload []byte, expectStatus int) []byte {
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	fatalf(err, "build request")
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	fatalf(err, "connect to coordinator (is 'karadul server' running?)")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != expectStatus {
		fmt.Fprintf(os.Stderr, "error: server returned %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	return body
}

func strOrDash(v interface{}) string {
	if v == nil {
		return "-"
	}
	s := fmt.Sprintf("%v", v)
	if s == "" {
		return "-"
	}
	return s
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
