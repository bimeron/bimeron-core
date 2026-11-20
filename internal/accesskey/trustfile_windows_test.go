package accesskey

import (
	"net/url"
	"testing"
)

// TestURIFileOptionsMustBeLocal checks that share URIs cannot name a network
// or device path for the SSH identity, known_hosts or MASQUE CA file.
func TestURIFileOptionsMustBeLocal(t *testing.T) {
	nonLocal := []string{
		`\\server\share\file`,
		`//server/share/file`,
		`\\server@SSL\DavWWWRoot\file`,
		`\\server@SSL@8443\DavWWWRoot\file`,
		`\\?\C:\file`,
		`\\?\UNC\server\share\file`,
		`\\.\pipe\bimeron-test`,
		`\??\C:\file`,
		`C:\keys\NUL`,
		`C:\keys\file:stream`,
	}
	for _, path := range nonLocal {
		v := url.QueryEscape(path)
		for option, field := range map[string]string{"known_hosts": "KnownHostsFile", "identity": "IdentityFile"} {
			checkProblem(t, "ssh "+option+" "+path, errOf(ParseSSH("ssh://alice@example.com?"+option+"="+v)), wantProblem{code: "file_path_not_local", field: field})
		}
		checkProblem(t, "masque ca "+path, errOf(ParseMASQUE("masque://example.com?ca="+v)), wantProblem{code: "file_path_not_local", field: "CAFile"})
	}
	local := `C:\Users\alice\.ssh\known_hosts`
	if p, err := ParseSSH("ssh://alice@example.com?known_hosts=" + url.QueryEscape(local) + "&identity=id_ed25519"); err != nil || p.SSH.KnownHostsFile != local || p.SSH.IdentityFile != "id_ed25519" {
		t.Fatalf("local SSH paths: %+v, %v", p.SSH, err)
	}
	if p, err := ParseMASQUE("masque://example.com?ca=" + url.QueryEscape(`C:\ca\proxy.pem`)); err != nil || p.MASQUE.CAFile != `C:\ca\proxy.pem` {
		t.Fatalf("local MASQUE CA: %+v, %v", p.MASQUE, err)
	}
}
