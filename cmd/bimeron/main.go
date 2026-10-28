package main

import (
	"bimeron/internal/accesskey"
	"bimeron/internal/routing"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		fmt.Println("bimeron version [-daemon]")
		fmt.Println("bimeron doctor [-output report.json] (read-only diagnostics)")
		fmt.Println("bimeron ikev2 profile -name <name> -server <DNS-name> [-apply | -remove] (Windows; preview by default)")
		fmt.Println("bimeron service install [-automatic] | update -source <absolute-path> -version <version> -sha256 <executable-sha256> | describe | start | stop | status | uninstall (Windows/Linux; Linux install also accepts -owner uid)")
		fmt.Println("bimeron daemon\nbimeron start <config-file>\nbimeron status\nbimeron watch\nbimeron stats (session traffic counters)\nbimeron capabilities (platform feature report)\nbimeron stop (disconnect session)\nbimeron shutdown (disconnect and exit daemon)")
		fmt.Println("bimeron run <config-file>\nbimeron validate <config-file>\nbimeron inspect <key-file>\nbimeron route <policy-file> <destination-IP> [domain]\nbimeron proxy [-listen 127.0.0.1:1080] [-policy file.json] <key-file>\nbimeron connect [-policy file.json] [-dns 1.1.1.1] <key-file>\nbimeron recover\nbimeron check [-dns 1.1.1.1] <key-file>")
		return nil
	}
	switch args[0] {
	case "ikev2":
		return ikev2Command(args[1:])
	case "version":
		return versionCommand(args[1:])
	case "doctor":
		return doctor(args[1:])
	case "service":
		return serviceCommand(args[1:])
	case "daemon":
		return daemon(args[1:])
	case "start", "status", "stop", "shutdown":
		return controlCommand(args[0], args[1:])
	case "watch":
		return watchControl(args[1:])
	case "stats":
		return statsControl(args[1:])
	case "capabilities":
		return capabilitiesControl(args[1:])
	case "run":
		return runConfig(args[1:])
	case "validate":
		return validateConfig(args[1:])
	case "check":
		return check(args[1:])
	case "connect":
		return connect(args[1:])
	case "recover":
		return recoverVPN(args[1:])
	case "proxy":
		return serve(args[1:])
	case "inspect":
		if len(args) != 2 {
			return fmt.Errorf("usage: bimeron inspect <key-file>")
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			return fmt.Errorf("could not read key file")
		}
		p, err := accesskey.NewResolver().Resolve(context.Background(), string(b))
		if err != nil {
			return err
		}
		// Never include the password, username, prefix, name or config URL in diagnostics.
		kind := p.Type
		if kind == "" {
			kind = "shadowsocks"
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"type": kind, "tcp": map[string]any{"host": p.TCP.Host, "port": p.TCP.Port, "cipher": p.TCP.Cipher}, "udp": map[string]any{"host": p.UDP.Host, "port": p.UDP.Port, "cipher": p.UDP.Cipher}})
	case "route":
		if len(args) < 3 || len(args) > 4 {
			return fmt.Errorf("usage: bimeron route <policy-file> <destination-IP> [domain]")
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			return fmt.Errorf("could not read policy")
		}
		var c routing.Config
		if err = json.Unmarshal(b, &c); err != nil {
			return fmt.Errorf("invalid policy JSON")
		}
		p, err := routing.Compile(c)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(args[2])
		if err != nil {
			return fmt.Errorf("invalid destination IP")
		}
		domain := ""
		if len(args) == 4 {
			domain = args[3]
		}
		fmt.Println(p.Decide(ip, domain))
		return nil
	default:
		return fmt.Errorf("unknown command")
	}
}
