package problem

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestCatalogLoads(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || len(c.Codes) == 0 {
		t.Fatalf("catalog = %+v", c)
	}
	data, err := JSON()
	if err != nil || !json.Valid(data) {
		t.Fatalf("JSON() = %q, %v", data, err)
	}
}

// codeUse matches code literals passed to the core's code constructors.
var codeUse = regexp.MustCompile(`(?:problem\.New|\bNew|\bfault|\bcodeFault)\(\s*"([a-z0-9_]+)"|Code:\s*"([a-z0-9_]+)"`)

// TestCatalogMatchesSource keeps catalog and code in sync: every code literal
// passed to a constructor has an entry, and every entry appears as a literal.
func TestCatalogMatchesSource(t *testing.T) {
	root := filepath.Join("..", "..")
	used := map[string][]string{}
	literals := map[string]bool{}
	literal := regexp.MustCompile(`"([a-z][a-z0-9_]*)"`)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "third_party", "testdata", "build", "dist", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		for _, m := range codeUse.FindAllStringSubmatch(text, -1) {
			code := m[1] + m[2]
			used[code] = append(used[code], path)
		}
		for _, m := range literal.FindAllStringSubmatch(text, -1) {
			literals[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c := MustLoad()
	var missing []string
	for code, paths := range used {
		if _, ok := c.Codes[code]; !ok && !nonCatalogLiteral[code] {
			missing = append(missing, fmt.Sprintf("%s (%s)", code, paths[0]))
		}
	}
	var unused []string
	for code := range c.Codes {
		if !literals[code] {
			unused = append(unused, code)
		}
	}
	sort.Strings(missing)
	sort.Strings(unused)
	if len(missing) > 0 {
		t.Errorf("codes without catalog entries:\n%s", strings.Join(missing, "\n"))
	}
	if len(unused) > 0 {
		t.Errorf("catalog entries not used in source:\n%s", strings.Join(unused, "\n"))
	}
}

// nonCatalogLiteral lists Code literals that are not error codes, such as
// event codes for normal state changes.
var nonCatalogLiteral = map[string]bool{"state": true, "connected": true}

func TestProblemNeverLeaksCauseText(t *testing.T) {
	cause := errors.New("secret-sentinel")
	p := New("unclassified", "safe text").In("AccessKey").On("Password", "secret-sentinel").Wrap(cause)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-sentinel") {
		t.Fatalf("problem leaked a secret: %s", data)
	}
	if !errors.Is(p, cause) || p.Value != Present {
		t.Fatalf("problem = %+v", p)
	}
	if got := New("unclassified", "x").On("Password", "").Value; got != Absent {
		t.Fatalf("empty value state = %q", got)
	}
}

func TestOfWrapsUnknownErrors(t *testing.T) {
	p := Of(fmt.Errorf("plain"))
	if p.Code != Unclassified || p.Message != "plain" {
		t.Fatalf("Of() = %+v", p)
	}
	wrapped := fmt.Errorf("context: %w", New("unclassified", "inner").At("Name"))
	if got := Of(wrapped); got.Field != "Name" {
		t.Fatalf("Of(wrapped) = %+v", got)
	}
	if got := List(nil); got == nil || len(got) != 0 {
		t.Fatalf("List(nil) = %#v", got)
	}
}

func TestTextFillsPlaceholders(t *testing.T) {
	if got := Text("no_such_code", "ru", nil); got != MustLoad().Codes[Unclassified].RU {
		t.Fatalf("unknown code text = %q", got)
	}
	c := &Catalog{Codes: map[string]Entry{}}
	_ = c
	if got := Placeholders("a {max} b {min} {max}"); strings.Join(got, ",") != "max,min" {
		t.Fatalf("Placeholders() = %v", got)
	}
}

func TestMergeRejectsDefects(t *testing.T) {
	for name, body := range map[string]string{
		"missing ru":   `{"codes":{"unclassified":{"kind":"config","en":"x","ru":""}}}`,
		"bad kind":     `{"codes":{"unclassified":{"kind":"x","en":"x","ru":"y"}}}`,
		"placeholders": `{"codes":{"unclassified":{"kind":"config","en":"{a}","ru":"{b}"}}}`,
		"bad code":     `{"codes":{"Bad-Code":{"kind":"config","en":"x","ru":"y"}}}`,
		"unknown key":  `{"codes":{},"extra":1}`,
	} {
		fsys := mapFS{"catalog/a.json": body}
		if _, err := merge(fsys); err == nil {
			t.Errorf("%s: merge accepted a defective catalog", name)
		}
	}
	dup := mapFS{
		"catalog/a.json": `{"codes":{"unclassified":{"kind":"config","en":"x","ru":"y"}}}`,
		"catalog/b.json": `{"codes":{"unclassified":{"kind":"config","en":"x","ru":"y"}}}`,
	}
	if _, err := merge(dup); err == nil {
		t.Error("merge accepted a duplicate code")
	}
}

type mapFS map[string]string

func (m mapFS) Open(name string) (fs.File, error) { return nil, fs.ErrNotExist }
func (m mapFS) ReadFile(name string) ([]byte, error) {
	if body, ok := m[name]; ok {
		return []byte(body), nil
	}
	return nil, fs.ErrNotExist
}
func (m mapFS) Glob(pattern string) ([]string, error) {
	var names []string
	for name := range m {
		if ok, _ := filepath.Match(pattern, name); ok {
			names = append(names, name)
		}
	}
	return names, nil
}
