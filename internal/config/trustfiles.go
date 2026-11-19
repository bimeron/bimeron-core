package config

import (
	"path/filepath"
	"runtime"
	"strings"
)

// Trust file kinds.
const (
	TrustSSHIdentity   = "ssh_identity"
	TrustSSHKnownHosts = "ssh_known_hosts"
	TrustMASQUECA      = "masque_ca"
)

// Trust file sources.
const (
	// TrustFromURI marks a path from a share URI query option, including a
	// URI read through Key or File.
	TrustFromURI = "uri"
	// TrustFromOption marks a path from an explicit [AccessKey] option.
	TrustFromOption = "option"
)

// TrustFile is a file that the profile makes Bimeron trust or use for
// authentication: an SSH identity, an SSH known_hosts file or a MASQUE CA.
type TrustFile struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	// Path is the path the session opens; see TrustFiles.
	Path string `json:"path"`
}

// TrustFiles lists the trust files that the profile references, in the order
// ssh_identity, ssh_known_hosts, masque_ca, so that a GUI can ask the user to
// confirm them. Dynamic keys (ssconf://) are resolved later and reference no
// trust files. The result is empty, not nil, when there are none.
//
// Each path is exactly the string the session opens. For a profile loaded
// from a file it is absolute: relative paths are resolved against the profile
// directory and the result is cleaned with filepath.Clean; on Windows the
// drive letter is upper case and separators are backslashes. Letter case is
// otherwise kept as written, and symbolic links, junctions and short names
// are not resolved: they are followed when the file is opened.
//
// A home-relative path ("~", "~/..." or "~\...") is reported as written. The
// account that runs the session resolves it against its own home directory,
// which for the system service is not the user's.
func (c *File) TrustFiles() []TrustFile {
	files := []TrustFile{}
	if c == nil || c.profile == nil {
		return files
	}
	add := func(kind, path, option string) {
		if path == "" {
			return
		}
		source := TrustFromURI
		if option != "" {
			source = TrustFromOption
		}
		files = append(files, TrustFile{Kind: kind, Source: source, Path: path})
	}
	switch c.profile.Type {
	case "ssh":
		add(TrustSSHIdentity, c.profile.SSH.IdentityFile, c.Access.IdentityFile)
		add(TrustSSHKnownHosts, c.profile.SSH.KnownHostsFile, c.Access.KnownHostsFile)
	case "masque":
		add(TrustMASQUECA, c.profile.MASQUE.CAFile, c.Access.CAFile)
	}
	return files
}

// normalizeTrustPaths stores the trust file paths of the profile in the form
// TrustFiles reports, so that the session opens exactly the reported paths.
func (c *File) normalizeTrustPaths() {
	if c.profile == nil {
		return
	}
	c.profile.SSH.IdentityFile = normalizeTrustPath(c.profile.SSH.IdentityFile)
	c.profile.SSH.KnownHostsFile = normalizeTrustPath(c.profile.SSH.KnownHostsFile)
	c.profile.MASQUE.CAFile = normalizeTrustPath(c.profile.MASQUE.CAFile)
}

func homeRelative(path string) bool {
	return path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`)
}

func normalizeTrustPath(path string) string {
	if path == "" || homeRelative(path) {
		return path
	}
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" && len(path) >= 2 && path[1] == ':' && 'a' <= path[0] && path[0] <= 'z' {
		path = strings.ToUpper(path[:1]) + path[1:]
	}
	return path
}
