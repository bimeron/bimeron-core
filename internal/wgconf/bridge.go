package wgconf

import (
	"slices"
	"strings"

	"bimeron/internal/problem"
)

// Formats reported by Detect.
const (
	FormatBimeron   = "bimeron"
	FormatWireGuard = "wireguard"
)

var bimeronSections = []string{"Profile", "AccessKey", "Routing", "Rule", "GeoData", "IKEv2", "ShadowTLS"}

// Detect classifies configuration text without validating it.
func Detect(text string) (string, error) {
	if err := checkText(text); err != nil {
		return "", err
	}
	d, _ := ParseDocument(text)
	bimeron, wireguard := false, false
	for _, s := range d.sections {
		if s.known && s.name == Peer {
			wireguard = true
		}
		for _, name := range bimeronSections {
			if strings.EqualFold(name, s.name) {
				bimeron = true
			}
		}
	}
	for _, l := range d.lines {
		if l.known && l.key == "PrivateKey" && d.sections[l.section].name == Interface {
			wireguard = true
		}
	}
	switch {
	case bimeron && wireguard:
		return "", problem.New("document_format_ambiguous", "text mixes Bimeron profile and WireGuard sections")
	case wireguard:
		return FormatWireGuard, nil
	case bimeron:
		return FormatBimeron, nil
	}
	return "", problem.New("document_format_unknown", "text is neither a Bimeron profile nor a WireGuard configuration")
}

// Inspection describes WireGuard text for editors. Fields hold secrets.
type Inspection struct {
	Format       string            `json:"format"`
	Protocol     string            `json:"protocol"`
	AWGVersion   string            `json:"awg_version"`
	Fields       map[string]string `json:"fields,omitempty"`
	FieldsError  string            `json:"fields_error,omitempty"`
	SecretFields []string          `json:"secret_fields"`
	AllowedIPs   AllowedIPs        `json:"allowed_ips"`
	Problems     []*problem.Error  `json:"problems"`
}

// Inspect reports fields and validation problems of a parsed document.
func (d *Document) Inspect() Inspection {
	protocol, version := d.Protocol()
	r := Inspection{Format: FormatWireGuard, Protocol: protocol, AWGVersion: version, SecretFields: slices.Clone(SecretFields), AllowedIPs: Summarize(d.AllowedIPs()), Problems: []*problem.Error{}}
	fields, err := d.Fields()
	if err != nil {
		r.FieldsError = "ambiguous WireGuard structure; use raw editing"
	} else {
		r.Fields = fields
	}
	if _, err := d.Config(); err != nil {
		r.Problems = problem.List(err)
	}
	return r
}

// Edit is one field operation of the bridge.
type Edit struct {
	Section, Key, Value string
}

// ApplyEdits applies edits in order. On failure the document is unchanged.
func (d *Document) ApplyEdits(edits []Edit) error {
	saved := slices.Clone(d.lines)
	for _, e := range edits {
		err := d.SetField(e.Section, e.Key, e.Value)
		if err == nil && len(d.String()) > MaxSize {
			err = problem.New("file_too_large", "WireGuard configuration exceeds size limit").Arg("limit", "64 KiB").InDocument(DocumentName)
		}
		if err != nil {
			d.lines = saved
			d.reindex()
			return err
		}
	}
	return nil
}
