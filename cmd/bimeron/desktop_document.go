package main

import (
	"bimeron/core"
	"bimeron/internal/config"
	"bimeron/internal/geofile"
	"bimeron/internal/problem"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"unicode/utf8"
)

const documentProfileLimit = 65536
const bridgeOutputLimit = 32 << 20

type documentOperation struct {
	Op      string  `json:"op"`
	Index   *int    `json:"index,omitempty"`
	To      *int    `json:"to,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
	Matcher string  `json:"matcher,omitempty"`
	Value   *string `json:"value,omitempty"`
	Action  string  `json:"action,omitempty"`
	Section string  `json:"section,omitempty"`
	Key     string  `json:"key,omitempty"`
}
type documentRequest struct {
	Version    int                  `json:"version"`
	Profile    *string              `json:"profile"`
	Operations *[]documentOperation `json:"operations"`
}
type bridgeResponse struct {
	Version     int                `json:"version"`
	Fields      json.RawMessage    `json:"fields,omitempty"`
	FieldsError string             `json:"fields_error,omitempty"`
	Profile     *string            `json:"profile,omitempty"`
	Rules       json.RawMessage    `json:"rules,omitempty"`
	Groups      *[]string          `json:"groups,omitempty"`
	Error       string             `json:"error,omitempty"`
	Details     *core.GeoDataError `json:"details,omitempty"`
	// Problems lists structured failures; see docs/ERRORS.MD. Validation
	// responses always include it, other bridge responses only on failure.
	Problems *[]*problem.Error `json:"problems,omitempty"`
}

func writeBridge(w io.Writer, r bridgeResponse, err error) error {
	r.Version = 1
	if err != nil {
		r.Error = "request failed"
		errors.As(err, &r.Details)
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
func documentBridge(in io.Reader, out io.Writer) error {
	r := bridgeResponse{}
	data, err := io.ReadAll(io.LimitReader(in, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || !utf8.Valid(data) {
		return writeBridge(out, r, fmt.Errorf("invalid request"))
	}
	var req documentRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err = dec.Decode(&req)
	if err == nil {
		var extra any
		if dec.Decode(&extra) != io.EOF {
			err = fmt.Errorf("trailing JSON")
		}
	}
	if err != nil || req.Version != 1 || req.Profile == nil || req.Operations == nil || len(*req.Profile) > documentProfileLimit {
		return writeBridge(out, r, fmt.Errorf("invalid request"))
	}
	original := core.ParseConfigDocument([]byte(*req.Profile))
	doc := core.ParseConfigDocument(original.Bytes())
	for _, op := range *req.Operations {
		if op.Op != "set_field" && op.Index == nil {
			err = fmt.Errorf("missing index")
			break
		}
		if (op.Op == "set_rule" || op.Op == "add" || op.Op == "set_field") && op.Value == nil {
			err = fmt.Errorf("missing value")
			break
		}
		switch op.Op {
		case "set_rule":
			err = doc.SetRule(*op.Index, op.Matcher, *op.Value, op.Action)
		case "toggle":
			if op.Enabled == nil {
				err = fmt.Errorf("missing enabled")
			} else {
				err = doc.SetRuleEnabled(*op.Index, *op.Enabled)
			}
		case "move":
			if op.To == nil {
				err = fmt.Errorf("missing to")
			} else {
				err = doc.MoveRule(*op.Index, *op.To)
			}
		case "add":
			if op.Enabled == nil {
				err = fmt.Errorf("missing enabled")
			} else {
				err = doc.InsertRule(*op.Index, op.Matcher, *op.Value, op.Action, *op.Enabled)
			}
		case "delete":
			err = doc.DeleteRule(*op.Index)
		case "set_field":
			err = doc.SetSectionField(op.Section, op.Key, *op.Value)
		default:
			err = fmt.Errorf("unknown operation")
		}
		if err == nil && len(doc.Bytes()) > documentProfileLimit {
			err = fmt.Errorf("profile limit exceeded")
		}
		if err != nil {
			break
		}
	}
	if err != nil {
		doc = original
	}
	profile := string(doc.Bytes())
	r.Profile = &profile
	rows, _ := doc.RulesJSON()
	r.Rules = json.RawMessage(rows)
	fields, fieldErr := doc.FieldsJSON()
	if fieldErr != nil {
		r.FieldsError = "ambiguous section fields; use raw editing"
	} else {
		r.Fields = json.RawMessage(fields)
	}

	return writeBridge(out, r, err)
}
func geoDataBridge(args []string, out io.Writer) error {
	groups := []string{}
	r := bridgeResponse{Groups: &groups}
	if len(args) != 3 || args[0] != "groups" || (args[1] != "geoip" && args[1] != "geosite") || !filepath.IsAbs(args[2]) {
		return writeBridge(out, r, fmt.Errorf("invalid arguments"))
	}
	f, err := geofile.Open(args[2])
	if err != nil {
		return writeBridge(out, r, &core.GeoDataError{Code: "geodata_unreadable", Kind: args[1]})
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return writeBridge(out, r, fmt.Errorf("not a regular file"))
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if err == nil && len(data) > 64<<20 {
		err = &core.GeoDataError{Code: "geodata_limit", Kind: args[1]}
	}
	if err == nil {
		groups, err = core.GeoDataGroups(args[1], data)
	}
	if groups == nil {
		groups = []string{}
	}
	return writeBridge(out, r, err)
}

func validateJSONBridge(path string, out io.Writer) error {
	if !filepath.IsAbs(path) {
		return writeBridge(out, bridgeResponse{}, problem.New("invalid_request", "absolute path required"))
	}
	_, err := config.Load(path)
	problems := problem.List(err)
	return writeBridge(out, bridgeResponse{Problems: &problems}, err)
}
