package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"bimeron/core"
	"bimeron/internal/problem"
	"bimeron/internal/wgconf"
)

type wireguardOperation struct {
	Op      string  `json:"op"`
	Section string  `json:"section"`
	Key     string  `json:"key"`
	Value   *string `json:"value"`
}

type wireguardRequest struct {
	Version    int                   `json:"version"`
	Op         string                `json:"op"`
	Text       *string               `json:"text,omitempty"`
	URI        *string               `json:"uri,omitempty"`
	PrivateKey *string               `json:"private_key,omitempty"`
	Operations *[]wireguardOperation `json:"operations,omitempty"`
}

// wireguardResponse is secret-bearing when Text or Fields are present.
type wireguardResponse struct {
	Version      int                         `json:"version"`
	Capabilities *core.WireGuardCapabilities `json:"capabilities,omitempty"`
	// Key operation results; secrets.
	PrivateKey   string             `json:"private_key,omitempty"`
	PublicKey    string             `json:"public_key,omitempty"`
	PresharedKey string             `json:"preshared_key,omitempty"`
	Format       string             `json:"format,omitempty"`
	Text         *string            `json:"text,omitempty"`
	Name         *string            `json:"name,omitempty"`
	Protocol     string             `json:"protocol,omitempty"`
	AWGVersion   *string            `json:"awg_version,omitempty"`
	Fields       map[string]string  `json:"fields,omitempty"`
	FieldsError  string             `json:"fields_error,omitempty"`
	SecretFields []string           `json:"secret_fields,omitempty"`
	AllowedIPs   *wgconf.AllowedIPs `json:"allowed_ips,omitempty"`
	Error        string             `json:"error,omitempty"`
	Problems     *[]*problem.Error  `json:"problems,omitempty"`
}

func (r *wireguardResponse) inspect(d *wgconf.Document, withText bool) {
	i := d.Inspect()
	r.Format, r.Protocol, r.AWGVersion = i.Format, i.Protocol, &i.AWGVersion
	r.Fields, r.FieldsError, r.SecretFields, r.AllowedIPs = i.Fields, i.FieldsError, i.SecretFields, &i.AllowedIPs
	r.Problems = &i.Problems
	if withText {
		text := d.String()
		r.Text = &text
	}
}

func writeWireGuard(w io.Writer, r wireguardResponse, err error) error {
	r.Version = 1
	if err != nil {
		r.Error = "request failed"
		problems := problem.List(err)
		r.Problems = &problems
	}
	b, marshalErr := json.Marshal(r)
	if marshalErr != nil {
		return marshalErr
	}
	if len(b) > bridgeOutputLimit {
		b = []byte(`{"version":1,"error":"response limit exceeded"}`)
	}
	_, writeErr := w.Write(append(b, '\n'))
	return writeErr
}

func invalidWireGuardRequest(message string) error {
	return problem.New("invalid_request", message)
}

// wireguardBridge serves "bimeron wireguard": one JSON request on stdin, one
// response on stdout. It never touches files, DNS or the network.
func wireguardBridge(in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(in, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || !utf8.Valid(data) {
		return writeWireGuard(out, wireguardResponse{}, invalidWireGuardRequest("invalid request"))
	}
	var req wireguardRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err = dec.Decode(&req)
	if err == nil {
		var extra any
		if dec.Decode(&extra) != io.EOF {
			err = fmt.Errorf("trailing JSON")
		}
	}
	if err != nil || req.Version != 1 {
		return writeWireGuard(out, wireguardResponse{}, invalidWireGuardRequest("invalid request"))
	}
	needsText := req.Op == "detect" || req.Op == "inspect" || req.Op == "edit"
	if needsText != (req.Text != nil) || (req.Op == "public_key") != (req.PrivateKey != nil) || (req.Op == "import_uri") != (req.URI != nil) || (req.Op == "edit") != (req.Operations != nil) {
		return writeWireGuard(out, wireguardResponse{}, invalidWireGuardRequest("invalid request members for operation"))
	}
	switch req.Op {
	case "generate_keypair":
		private, public, err := wgconf.GenerateKeyPair()
		if err != nil {
			return writeWireGuard(out, wireguardResponse{}, problem.New("unclassified", "key generation failed"))
		}
		return writeWireGuard(out, wireguardResponse{PrivateKey: private, PublicKey: public}, nil)
	case "public_key":
		public, err := wgconf.PublicKey(*req.PrivateKey)
		return writeWireGuard(out, wireguardResponse{PublicKey: public}, err)
	case "generate_preshared_key":
		psk, err := wgconf.GeneratePresharedKey()
		if err != nil {
			return writeWireGuard(out, wireguardResponse{}, problem.New("unclassified", "key generation failed"))
		}
		return writeWireGuard(out, wireguardResponse{PresharedKey: psk}, nil)
	case "capabilities":
		return writeWireGuard(out, wireguardResponse{Capabilities: core.WireGuardSupport()}, nil)
	case "detect":
		format, err := wgconf.Detect(*req.Text)
		if err != nil {
			problem.Of(err).InDocument(wgconf.DocumentName)
		}
		return writeWireGuard(out, wireguardResponse{Format: format}, err)
	case "inspect":
		d, err := wgconf.ParseDocument(*req.Text)
		if err != nil {
			return writeWireGuard(out, wireguardResponse{}, err)
		}
		r := wireguardResponse{}
		r.inspect(d, false)
		return writeWireGuard(out, r, nil)
	case "edit":
		d, err := wgconf.ParseDocument(*req.Text)
		if err != nil {
			return writeWireGuard(out, wireguardResponse{}, err)
		}
		edits := make([]wgconf.Edit, 0, len(*req.Operations))
		for _, op := range *req.Operations {
			if op.Op != "set_field" || op.Value == nil {
				r := wireguardResponse{}
				r.inspect(d, true)
				return writeWireGuard(out, r, invalidWireGuardRequest("unknown or incomplete edit operation"))
			}
			edits = append(edits, wgconf.Edit{Section: op.Section, Key: op.Key, Value: *op.Value})
		}
		editErr := d.ApplyEdits(edits)
		r := wireguardResponse{}
		r.inspect(d, true)
		return writeWireGuard(out, r, editErr)
	case "import_uri":
		imported, err := wgconf.ImportURI(*req.URI)
		if err != nil {
			return writeWireGuard(out, wireguardResponse{}, err)
		}
		d, err := wgconf.ParseDocument(imported.Text)
		if err != nil {
			return writeWireGuard(out, wireguardResponse{}, err)
		}
		r := wireguardResponse{Name: &imported.Name}
		r.inspect(d, true)
		return writeWireGuard(out, r, nil)
	}
	return writeWireGuard(out, wireguardResponse{}, invalidWireGuardRequest("unknown operation"))
}
