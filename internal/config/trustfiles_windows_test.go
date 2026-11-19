package config

import "testing"

func TestTrustFileOptionsMustBeLocal(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ access, field string }{
		{`SSH = ssh://alice@example.com` + "\n" + `KnownHostsFile = \\server\share\known_hosts`, "KnownHostsFile"},
		{`SSH = ssh://alice@example.com` + "\n" + `IdentityFile = \\server@SSL\DavWWWRoot\id`, "IdentityFile"},
		{"Type = ssh\nServer = example.com\nPort = 22\nUsername = alice\n" + `KnownHostsFile = \\?\C:\known_hosts`, "KnownHostsFile"},
		{"Type = masque\nServer = proxy.example\nPort = 443\n" + `CAFile = \\server\share\ca.pem`, "CAFile"},
		{`SSH = ssh://alice@example.com?known_hosts=%5C%5Cserver%5Cshare%5Ckh`, "KnownHostsFile"},
		{`MASQUE = masque://proxy.example?ca=%5C%5Cserver%5Cshare%5Cca.pem`, "CAFile"},
		{"SSH = ssh://alice@example.com\nKnownHostsFile = D:known_hosts", "KnownHostsFile"},
		{"SSH = ssh://alice@example.com?identity=C:id", "IdentityFile"},
	} {
		p := loadProblem(t, dir, "[Profile]\nVersion = 1\n\n[AccessKey]\n"+tc.access+"\n")
		if p.Code != "file_path_not_local" || p.Section != "AccessKey" || p.Field != tc.field {
			t.Errorf("%q: problem = %+v", tc.access, *p)
		}
	}
}

func TestTrustFilePathNormalization(t *testing.T) {
	for in, want := range map[string]string{
		`c:\Users\a\..\b\kh`: `C:\Users\b\kh`,
		`C:/Users/a/kh`:      `C:\Users\a\kh`,
		`d:\Keys\ID`:         `D:\Keys\ID`,
	} {
		if got := normalizeTrustPath(in); got != want {
			t.Errorf("normalizeTrustPath(%q) = %q, want %q", in, got, want)
		}
	}
}
