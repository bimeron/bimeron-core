package config

import "testing"

func TestTrojanSources(t *testing.T) {
	for _, source := range []string{
		"Trojan = trojan://secret@example.com:443?sni=front.example.com",
		"Key = trojan://secret@example.com:443?sni=front.example.com",
		"Type = trojan\nServer = example.com\nPort = 443\nPassword = secret\nServerName = front.example.com",
	} {
		file, err := ParseData([]byte("[Profile]\nVersion = 1\n[AccessKey]\n" + source + "\n[Interface]\nMode = proxy\n"))
		if err != nil {
			t.Fatal(err)
		}
		profile, err := file.Resolve(nil)
		if err != nil || profile.Type != "trojan" || profile.Trojan.ServerName != "front.example.com" {
			t.Fatalf("invalid profile: %+v, %v", profile, err)
		}
	}
}

func TestTrojanTransportParameters(t *testing.T) {
	base := "[Profile]\nVersion = 1\n[AccessKey]\nType = trojan\nServer = example.com\nPort = 443\nPassword = secret\n"
	for _, options := range []string{"Network = ws\nWSPath = /proxy\nWSHost = front.example.com\nALPN = http/1.1\n", "Network = grpc\nSecurity = tls\nGRPCServiceName = proxy\nGRPCAuthority = front.example.com\nGRPCMultiMode = true\nALPN = h2\n"} {
		file, err := ParseData([]byte(base + options))
		if err != nil {
			t.Fatal(err)
		}
		p, err := file.Resolve(nil)
		if err != nil || p.Trojan.Network == "" {
			t.Fatalf("invalid transport: %v", err)
		}
	}
	for _, options := range []string{"Network = grpc\n", "Network = ws\nALPN = h2\n", "Network = ws\nID = forbidden\n", "Network = grpc\nGRPCServiceName = proxy\nSecurity = reality\n", "Network = ws\nWSEarlyData = 2048\n", "Network = ws\nWSEarlyData = 0\n"} {
		if _, err := ParseData([]byte(base + options)); err == nil {
			t.Fatalf("accepted %s", options)
		}
	}
}
