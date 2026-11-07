package problem

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Catalog fragments live in catalog/*.json, one file per area, and are merged
// at first use. Duplicate codes or fields are a build defect.
//
//go:embed catalog/*.json
var fragments embed.FS

// Kinds of catalog entries.
const (
	KindConfig     = "config"
	KindControl    = "control"
	KindConnection = "connection"
)

// Languages lists the catalog languages in fallback order.
var Languages = []string{"en", "ru"}

// Entry holds the texts of one code.
type Entry struct {
	Kind string `json:"kind"`
	EN   string `json:"en"`
	RU   string `json:"ru"`
}

// Catalog is the merged, versioned catalog returned to clients.
type Catalog struct {
	Version      int                 `json:"version"`
	Languages    []string            `json:"languages"`
	SecretFields []string            `json:"secret_fields"`
	URIFields    map[string][]string `json:"uri_fields"`
	Codes        map[string]Entry    `json:"codes"`
}

type fragment struct {
	SecretFields []string            `json:"secret_fields"`
	URIFields    map[string][]string `json:"uri_fields"`
	Codes        map[string]Entry    `json:"codes"`
}

var (
	loadOnce sync.Once
	loaded   *Catalog
	loadErr  error
	codeName = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
)

// Load returns the merged catalog.
func Load() (*Catalog, error) {
	loadOnce.Do(func() { loaded, loadErr = merge(fragments) })
	return loaded, loadErr
}

// MustLoad panics on a malformed embedded catalog; tests guard against it.
func MustLoad() *Catalog {
	c, err := Load()
	if err != nil {
		panic(err)
	}
	return c
}

// JSON returns the catalog document served to clients.
func JSON() ([]byte, error) {
	c, err := Load()
	if err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// Known reports whether code has a catalog entry.
func Known(code string) bool {
	c, err := Load()
	if err != nil {
		return false
	}
	_, ok := c.Codes[code]
	return ok
}

// Text renders code in lang ("en" or "ru") with args. Unknown codes render the
// Unclassified text.
func Text(code, lang string, args map[string]string) string {
	c := MustLoad()
	entry, ok := c.Codes[code]
	if !ok {
		entry = c.Codes[Unclassified]
	}
	text := entry.EN
	if lang == "ru" && entry.RU != "" {
		text = entry.RU
	}
	for name, value := range args {
		text = strings.ReplaceAll(text, "{"+name+"}", value)
	}
	return text
}

var placeholder = regexp.MustCompile(`\{([a-z_]+)\}`)

// Placeholders returns the sorted placeholder names used by text.
func Placeholders(text string) []string {
	seen := map[string]bool{}
	for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
		seen[m[1]] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func merge(fsys fs.FS) (*Catalog, error) {
	names, err := fs.Glob(fsys, "catalog/*.json")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	c := &Catalog{Version: 1, Languages: Languages, URIFields: map[string][]string{}, Codes: map[string]Entry{}}
	secrets := map[string]bool{}
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		var f fragment
		if err := strictJSON(data, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for code, entry := range f.Codes {
			if _, dup := c.Codes[code]; dup {
				return nil, fmt.Errorf("%s: duplicate code %q", name, code)
			}
			if !codeName.MatchString(code) {
				return nil, fmt.Errorf("%s: malformed code %q", name, code)
			}
			if entry.Kind != KindConfig && entry.Kind != KindControl && entry.Kind != KindConnection {
				return nil, fmt.Errorf("%s: code %q has unknown kind %q", name, code, entry.Kind)
			}
			if strings.TrimSpace(entry.EN) == "" || strings.TrimSpace(entry.RU) == "" {
				return nil, fmt.Errorf("%s: code %q needs en and ru texts", name, code)
			}
			if strings.Join(Placeholders(entry.EN), ",") != strings.Join(Placeholders(entry.RU), ",") {
				return nil, fmt.Errorf("%s: code %q has different en and ru placeholders", name, code)
			}
			c.Codes[code] = entry
		}
		for _, field := range f.SecretFields {
			if secrets[field] {
				return nil, fmt.Errorf("%s: duplicate secret field %q", name, field)
			}
			secrets[field] = true
			c.SecretFields = append(c.SecretFields, field)
		}
		for field, protocols := range f.URIFields {
			if _, dup := c.URIFields[field]; dup {
				return nil, fmt.Errorf("%s: duplicate URI field %q", name, field)
			}
			c.URIFields[field] = protocols
		}
	}
	if _, ok := c.Codes[Unclassified]; !ok {
		return nil, fmt.Errorf("catalog lacks %q", Unclassified)
	}
	sort.Strings(c.SecretFields)
	return c, nil
}

func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}
