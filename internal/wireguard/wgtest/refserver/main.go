// Command refserver runs an upstream wireguard-go or amneziawg-go server
// process with a kernel TUN device for reference tests. It is the entry
// point of a disposable test container (Linux only):
//
//	refserver -server /amneziawg-go -socket /var/run/amneziawg/wg0.sock
//
// The device configuration comes from WGREF_UAPI in configuration protocol
// form, without the leading "set=1" line. refserver starts the server in the
// foreground, applies the configuration through the UAPI socket, gives the
// interface the tunnel addresses 10.77.0.1/24 and fd77::1/64, brings it up
// and runs TCP and UDP echo on port 7 of both addresses. It prints "ready"
// once everything is up and runs until SIGTERM, SIGINT or the server exits.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	server := flag.String("server", "", "server executable: wireguard-go or amneziawg-go")
	socket := flag.String("socket", "", "UAPI socket path of interface wg0")
	flag.Parse()
	if *server == "" || *socket == "" || os.Getenv("WGREF_UAPI") == "" {
		fmt.Fprintln(os.Stderr, "usage: WGREF_UAPI=<config> refserver -server PATH -socket PATH")
		os.Exit(2)
	}
	if err := run(*server, *socket, os.Getenv("WGREF_UAPI")); err != nil {
		fmt.Fprintln(os.Stderr, "refserver:", err)
		os.Exit(1)
	}
}
