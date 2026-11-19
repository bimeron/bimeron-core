package config

import (
	"os"
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
	// Path is absolute and cleaned; see TrustFiles.
	Path string `json:"path"`
}

// TrustFiles lists the trust files that the profile references, in the order
// ssh_identity, ssh_known_hosts, masque_ca, so that a GUI can ask the user to
// confirm them. Dynamic keys (ssconf://) are resolved later and reference no
// trust files.
//
// Each path is the path Bimeron opens: relative paths are resolved against
// the directory of a profile loaded from a file, "~" paths against the home
// directory of the current user, and the result is cleaned with
// filepath.Clean. On Windows the drive
// letter is upper case and separators are backslashes. Letter case is
// otherwise kept as written, and symbolic links, junctions and short names
// are not resolved: Bimeron opens the path as written and follows links when
// it opens the file. A home-relative path is reported unchanged if the home
// directory is unknown.
func (c *File) TrustFiles() []TrustFile {
	if c == nil || c.profile == nil {
		return nil
	}
	var files []TrustFile
	add := func(kind, path, option string) {
		if path == "" {
			return
		}
		source := TrustFromURI
		if option != "" {
			source = TrustFromOption
		}
		files = append(files, TrustFile{Kind: kind, Source: source, Path: normalizeTrustPath(path)})
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

func normalizeTrustPath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		path = filepath.Join(home, path[1:])
	}
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" && len(path) >= 2 && path[1] == ':' && 'a' <= path[0] && path[0] <= 'z' {
		path = strings.ToUpper(path[:1]) + path[1:]
	}
	return path
}
