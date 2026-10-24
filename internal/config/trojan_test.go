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
