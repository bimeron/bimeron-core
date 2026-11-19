package safefile

import (
	"path/filepath"
	"strings"
)

// local accepts drive-letter, rooted and relative paths whose elements are not
// reserved device names or stream names. UNC paths (\\server\share, //server),
// device-namespace paths (\\?\, \\.\, \??\) and drive-relative paths (C:file,
// which depend on the current directory of that drive) are rejected.
func local(path string) bool {
	if len(path) >= 2 && isSlash(path[0]) && isSlash(path[1]) {
		return false
	}
	if strings.HasPrefix(path, `\??\`) || strings.HasPrefix(path, `/??/`) {
		return false
	}
	volume := filepath.VolumeName(path)
	if volume != "" && (len(volume) != 2 || volume[1] != ':' || len(path) == 2 || !isSlash(path[2])) {
		return false
	}
	for _, element := range strings.FieldsFunc(path[len(volume):], func(r rune) bool { return r < 0x80 && isSlash(byte(r)) }) {
		// IsLocal rejects reserved device names such as NUL, CON or COM1.txt
		// and names with a colon.
		if element != "." && element != ".." && !filepath.IsLocal(element) {
			return false
		}
	}
	return true
}

func isSlash(c byte) bool { return c == '\\' || c == '/' }
