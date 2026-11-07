package core

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"bimeron/internal/problem"
)

var geoDataDocumentID = regexp.MustCompile(`\A[A-Za-z0-9_!-]{1,256}\z`)

// ConfigDocument is an in-memory, byte-preserving configuration draft. It never
// reads files or validates runnable policy, capabilities, or dataset membership.
// It is not safe for concurrent use. Row indexes follow the current rule order.
type ConfigDocument struct {
	prefix string
	parts  []configDocumentPart
}
type configDocumentPart struct {
	raw, alternate string
	rule, disabled bool
}

// ConfigDocumentRule describes a table row. Error explains malformed active
// rules or fields the table cannot safely edit. Disabled candidates are included
// only when structurally valid. Enabled is editor state, never a config option.
type ConfigDocumentRule struct {
	Index    int    `json:"index"`
	Enabled  bool   `json:"enabled"`
	Matcher  string `json:"matcher"`
	Value    string `json:"value"`
	Action   string `json:"action"`
	Editable bool   `json:"editable"`
	Error    string `json:"error,omitempty"`
}

// ParseConfigDocument retains arbitrary drafts, including unknown sections and
// invalid active rules. Unchanged Bytes always returns the original bytes.
func ParseConfigDocument(data []byte) *ConfigDocument {
	d := &ConfigDocument{}
	text := string(data)
	if strings.HasPrefix(text, "\ufeff") {
		d.prefix = "\ufeff"
		text = strings.TrimPrefix(text, d.prefix)
	}
	lines := documentLines(text)
	for i := 0; i < len(lines); {
		name, disabled := documentHeader(lines[i])
		if name != "Rule" {
			d.parts = append(d.parts, configDocumentPart{raw: lines[i]})
			i++
			continue
		}
		end := i + 1
		for end < len(lines) {
			h, _ := documentHeader(lines[end])
			if h != "" {
				break
			}
			if disabled && strings.TrimSpace(lines[end]) != "" && !strings.HasPrefix(strings.TrimSpace(lines[end]), "#") {
				break
			}
			end++
		}
		raw := strings.Join(lines[i:end], "")
		p := configDocumentPart{raw: raw, rule: true, disabled: disabled}
		if disabled {
			_, structural, _ := documentRule(documentUncomment(raw))
			p.rule = structural == nil
		}
		d.parts = append(d.parts, p)
		i = end
	}
	return d
}

// Bytes returns a detached copy of the draft, without runtime serialization.
func (d *ConfigDocument) Bytes() []byte {
	var b strings.Builder
	b.WriteString(d.prefix)
	for _, p := range d.parts {
		b.WriteString(p.raw)
	}
	return []byte(b.String())
}

// RuleCount includes active rules and structurally valid disabled candidates.
func (d *ConfigDocument) RuleCount() int {
	n := 0
	for _, p := range d.parts {
		if p.rule {
			n++
		}
	}
	return n
}
func (d *ConfigDocument) part(index int) (int, error) {
	n := 0
	for i, p := range d.parts {
		if p.rule {
			if n == index {
				return i, nil
			}
			n++
		}
	}
	return 0, problem.New("rule_index_out_of_range", "rule index out of range").In("Rule")
}

// atRule records the profile [Rule] index of the row in a problem. Disabled
// rows are comments to the profile parser and therefore have no index.
func (d *ConfigDocument) atRule(err error, index int) error {
	p, ok := problem.As(err)
	if !ok {
		return err
	}
	active := 0
	for _, part := range d.parts {
		if !part.rule {
			continue
		}
		if !part.disabled {
			active++
		}
		if index == 0 {
			if !part.disabled {
				p.AtRule(active)
			}
			break
		}
		index--
	}
	return p
}

// documentRuleFields are the canonical [Rule] options used as problem fields.
var documentRuleFields = map[string]bool{"CIDR": true, "Domain": true, "GeoIP": true, "GeoSite": true, "Action": true}

// ruleProblem places a problem in [Rule]; only canonical keys become fields.
func ruleProblem(code, message, field string) *problem.Error {
	p := problem.New(code, message).In("Rule")
	if documentRuleFields[field] {
		p.At(field)
	}
	return p
}

// documentBlocked prefixes a row problem message, keeping its code and location.
func documentBlocked(prefix string, row error) *problem.Error {
	p := *problem.Of(row)
	p.Message = prefix + p.Message
	return p.Wrap(row)
}

// Rule returns a detached row snapshot.
func (d *ConfigDocument) Rule(index int) (*ConfigDocumentRule, error) {
	r, _, err := d.rule(index)
	return r, err
}

// rule also returns the row problem that blocks editing, if any.
func (d *ConfigDocument) rule(index int) (*ConfigDocumentRule, error, error) {
	i, err := d.part(index)
	if err != nil {
		return nil, nil, err
	}
	p := d.parts[i]
	raw := p.raw
	if p.disabled {
		raw = documentUncomment(raw)
	}
	r, structural, unknown := documentRule(raw)
	r.Index = index
	r.Enabled = !p.disabled
	blocked := structural
	if blocked == nil {
		blocked = unknown
	}
	r.Editable = blocked == nil
	if blocked != nil {
		r.Error = blocked.Error()
	}
	return &r, blocked, nil
}

// RulesJSON provides the row array using only gomobile-compatible bridge types.
func (d *ConfigDocument) RulesJSON() (string, error) {
	rows := make([]*ConfigDocumentRule, 0, d.RuleCount())
	for i := 0; i < d.RuleCount(); i++ {
		r, err := d.Rule(i)
		if err != nil {
			return "", err
		}
		rows = append(rows, r)
	}
	b, err := json.Marshal(rows)
	return string(b), err
}

// SetRuleEnabled adds/removes one outer # layer on every nonblank line.
// Enabling checks structure and refuses unknown fields; callers must additionally
// validate runtime policy and datasets before applying the returned draft.
func (d *ConfigDocument) SetRuleEnabled(index int, enabled bool) error {
	i, err := d.part(index)
	if err != nil {
		return err
	}
	p := &d.parts[i]
	if enabled == !p.disabled {
		return nil
	}
	if enabled {
		if _, blocked, _ := d.rule(index); blocked != nil {
			return d.atRule(documentBlocked("cannot enable rule: ", blocked), index)
		}
	}
	next := p.alternate
	if next == "" {
		if enabled {
			next = documentUncomment(p.raw)
		} else {
			for _, line := range documentLines(p.raw) {
				if strings.TrimSpace(line) != "" {
					next += "# " + line
				} else {
					next += line
				}
			}
		}
	}
	p.alternate, p.raw = p.raw, next
	p.disabled = !enabled
	return nil
}

// SetRule replaces only the matcher key/value and action value, retaining their
// indentation, spacing, line endings, comments and position. Unknown fields or
// malformed rows block editing rather than silently discarding content.
func (d *ConfigDocument) SetRule(index int, matcher, value, action string) error {
	if err := documentCheck(matcher, value, action); err != nil {
		return d.atRule(err, index)
	}
	i, err := d.part(index)
	if err != nil {
		return err
	}
	r, blocked, _ := d.rule(index)
	if blocked != nil {
		return d.atRule(documentBlocked("cannot edit rule: ", blocked), index)
	}
	p := &d.parts[i]
	lines := documentLines(p.raw)
	for j, line := range lines {
		prefix := ""
		body := line
		if p.disabled && strings.TrimSpace(line) != "" {
			prefix, body = documentOuter(line)
		}
		key, _, ok := strings.Cut(strings.TrimSpace(body), "=")
		key = strings.TrimSpace(key)
		if !ok || (key != r.Matcher && key != "Action") {
			continue
		}
		eq := strings.IndexByte(body, '=')
		left := body[:eq]
		right := body[eq+1:]
		replacement := value
		newKey := matcher
		if key == "Action" {
			replacement = action
			newKey = "Action"
		}
		// The runtime decodes values beginning with a double quote.
		if strings.HasPrefix(replacement, `"`) {
			replacement = strconv.Quote(replacement)
		}
		leading := left[:len(left)-len(strings.TrimLeft(left, " \t"))]
		trailing := left[len(strings.TrimRight(left, " \t")):]
		ws := right[:len(right)-len(strings.TrimLeft(right, " \t"))]
		tail := right[len(strings.TrimRight(right, " \t\r\n")):]
		lines[j] = prefix + leading + newKey + trailing + "=" + ws + replacement + tail
	}
	p.raw = strings.Join(lines, "")
	p.alternate = ""
	d.separateRule(i, documentEOL(string(d.Bytes())))
	return nil
}

// MoveRule moves the complete block to a final zero-based row index. Text
// outside rule blocks stays in its relative position. A missing final newline
// stays missing; changed adjacency boundaries gain a missing blank separator.
func (d *ConfigDocument) MoveRule(from, to int) error {
	a, err := d.part(from)
	if err != nil {
		return err
	}
	b, err := d.part(to)
	if err != nil {
		return err
	}
	if a == b {
		return nil
	}
	original := string(d.Bytes())
	p := d.parts[a]
	if a < b {
		copy(d.parts[a:b], d.parts[a+1:b+1])
	} else {
		copy(d.parts[b+1:a+1], d.parts[b:a])
	}
	d.parts[b] = p
	eol := "\n"
	if strings.Contains(original, "\r\n") {
		eol = "\r\n"
	}
	for i := 0; i < len(d.parts)-1; i++ {
		if d.parts[i].raw != "" && !strings.HasSuffix(d.parts[i].raw, "\n") {
			d.parts[i].raw += eol
			d.parts[i].alternate = ""
		}
	}
	seams := []int{a - 1, b - 1, b}
	if a > b {
		seams = []int{b - 1, b, a}
	}
	for _, i := range seams {
		if i < 0 || i+1 >= len(d.parts) {
			continue
		}
		gap := documentGap(d.parts[i].raw, d.parts[i+1].raw, eol)
		d.parts[i].raw += gap
		if d.parts[i].alternate != "" {
			d.parts[i].alternate += gap
		}
	}
	if !strings.HasSuffix(original, "\n") && len(d.parts) > 0 {
		p := &d.parts[len(d.parts)-1]
		if p.rule && strings.HasSuffix(p.raw, "\n") {
			p.raw = strings.TrimSuffix(strings.TrimSuffix(p.raw, "\n"), "\r")
			p.alternate = ""
		}
	}
	return nil
}

// documentGap adds only the missing blank separator; existing whitespace survives.
func documentGap(left, right, eol string) string {
	if left == "" || right == "" {
		return ""
	}
	if strings.TrimSpace(documentLines(right)[0]) == "" {
		if !strings.HasSuffix(left, "\n") {
			return eol
		}
		return ""
	}
	lines := documentLines(left)
	last := lines[len(lines)-1]
	if strings.TrimSpace(last) == "" {
		if strings.HasSuffix(left, "\n") {
			return ""
		}
		return eol
	}
	if strings.HasSuffix(left, "\n") {
		return eol
	}
	return eol + eol
}

func (d *ConfigDocument) separateRule(i int, eol string) {
	if i > 0 {
		p := &d.parts[i-1]
		gap := documentGap(p.raw, d.parts[i].raw, eol)
		if gap != "" {
			p.raw += gap
			if p.alternate != "" {
				p.alternate += gap
			}
		}
	}
	if i+1 < len(d.parts) {
		p := &d.parts[i]
		gap := documentGap(p.raw, d.parts[i+1].raw, eol)
		if gap != "" {
			p.raw += gap
			if p.alternate != "" {
				p.alternate += gap
			}
		}
	}
}

func documentEOL(text string) string {
	if strings.Contains(text, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

func documentLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}
func documentOuter(line string) (string, string) {
	i := strings.IndexByte(line, '#')
	if i < 0 {
		return "", line
	}
	end := i + 1
	if end < len(line) && line[end] == ' ' {
		end++
	}
	return line[:end], line[end:]
}
func documentUncomment(raw string) string {
	var b strings.Builder
	for _, line := range documentLines(raw) {
		if strings.TrimSpace(line) != "" {
			prefix, body := documentOuter(line)
			line = prefix[:strings.IndexByte(prefix, '#')] + body
		}
		b.WriteString(line)
	}
	return b.String()
}
func documentHeader(line string) (string, bool) {
	s := strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	disabled := strings.HasPrefix(s, "#")
	if disabled {
		_, s = documentOuter(s)
		s = strings.TrimSpace(s)
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		name := strings.TrimSpace(s[1 : len(s)-1])
		if !disabled || name == "Rule" {
			return name, disabled
		}
	}
	return "", false
}

func documentRule(raw string) (ConfigDocumentRule, error, error) {
	r := ConfigDocumentRule{}
	seen := map[string]bool{}
	var matchers []string
	var structural, unknown error
	lines := documentLines(raw)
	for _, line := range lines[1:] {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		key, value, ok := strings.Cut(s, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" {
			structural = ruleProblem("syntax_invalid", "malformed or duplicate rule field", "")
			continue
		}
		if seen[key] {
			structural = ruleProblem("option_duplicate", "malformed or duplicate rule field", key)
			continue
		}
		seen[key] = true
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				structural = ruleProblem("syntax_invalid", "invalid quoted rule value", key)
				continue
			}
			value = decoded
		}
		switch key {
		case "CIDR", "Domain", "GeoIP", "GeoSite":
			matchers = append(matchers, key)
			r.Matcher = key
			r.Value = value
		case "Action":
			r.Action = value
		default:
			unknown = ruleProblem("option_unknown", fmt.Sprintf("unknown rule field %q; use raw editing", key), "")
		}
	}
	if len(matchers) == 0 {
		structural = ruleProblem("rule_matcher_count", "rule requires exactly one matcher", "")
	} else if len(matchers) > 1 {
		structural = ruleProblem("rule_matcher_count", "rule requires exactly one matcher", matchers[0]).Also(matchers[1:]...)
	}
	if err := documentValidate(r.Matcher, r.Value, r.Action); err != nil {
		structural = err
	}
	return r, structural, unknown
}

// documentCheck validates an edited row before it replaces document text.
func documentCheck(matcher, value, action string) error {
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return ruleProblem("value_has_invalid_characters", "invalid rule value", matcher)
	}
	if strings.TrimSpace(action) != action || strings.ContainsAny(action, "\r\n") {
		return ruleProblem("value_has_invalid_characters", "invalid rule value", "Action")
	}
	return documentValidate(matcher, value, action)
}

func documentValidate(matcher, value, action string) error {
	if strings.ContainsAny(value, "\r\n") {
		return ruleProblem("value_has_invalid_characters", "invalid rule value", matcher)
	}
	if strings.ContainsAny(action, "\r\n") {
		return ruleProblem("value_has_invalid_characters", "invalid rule value", "Action")
	}
	if action == "" {
		return ruleProblem("value_required", "invalid rule action", "").On("Action", "")
	}
	if action != "direct" && action != "proxy" && action != "block" {
		return ruleProblem("choice_invalid", "invalid rule action", "Action").Arg("allowed", "direct, proxy, block")
	}
	// invalid reports an empty matcher value as missing rather than malformed.
	invalid := func(code, message string) error {
		if value == "" {
			code = "value_required"
		}
		return ruleProblem(code, message, "").On(matcher, value)
	}
	switch matcher {
	case "CIDR":
		for _, v := range strings.Split(value, ",") {
			if _, err := netip.ParsePrefix(strings.TrimSpace(v)); err != nil {
				return invalid("cidr_invalid", "invalid CIDR")
			}
		}
	case "Domain":
		v := strings.TrimSuffix(value, ".")
		if v == "" || strings.ContainsAny(v, " /*:\t\r\n") {
			return invalid("domain_invalid", "invalid domain")
		}
	case "GeoIP", "GeoSite":
		for _, v := range strings.Split(value, ",") {
			v = strings.TrimSpace(v)
			if !geoDataDocumentID.MatchString(v) {
				return invalid("geodata_identifier_invalid", "invalid geodata identifier")
			}
		}
	default:
		return ruleProblem("choice_invalid", "invalid matcher", "").Arg("allowed", "CIDR, Domain, GeoIP, GeoSite")
	}
	return nil
}

// InsertRule inserts a new block before index, or appends at RuleCount().
func (d *ConfigDocument) InsertRule(index int, matcher, value, action string, enabled bool) error {
	if index < 0 || index > d.RuleCount() {
		return problem.New("rule_index_out_of_range", "rule index out of range").In("Rule")
	}
	// The new row has no profile index yet, so its problems carry none.
	if err := documentCheck(matcher, value, action); err != nil {
		return err
	}
	candidate := ParseConfigDocument([]byte("[Rule]\nDomain=example.com\nAction=direct\n"))
	if err := candidate.SetRule(0, matcher, value, action); err != nil {
		return err
	}
	if err := candidate.SetRuleEnabled(0, enabled); err != nil {
		return err
	}
	eol := "\n"
	if strings.Contains(string(d.Bytes()), "\r\n") {
		eol = "\r\n"
	}
	raw := strings.ReplaceAll(string(candidate.Bytes()), "\n", eol)
	at := len(d.parts)
	if index < d.RuleCount() {
		at, _ = d.part(index)
	}
	d.parts = append(d.parts, configDocumentPart{})
	copy(d.parts[at+1:], d.parts[at:])
	d.parts[at] = configDocumentPart{raw: raw, rule: true, disabled: !enabled}
	d.separateRule(at, eol)
	return nil
}

// DeleteRule removes the whole block, including comments owned by that block.
func (d *ConfigDocument) DeleteRule(index int) error {
	i, err := d.part(index)
	if err != nil {
		return err
	}
	d.parts = append(d.parts[:i], d.parts[i+1:]...)
	return nil
}

// SetSectionField patches a single non-Rule section without runtime validation.
// Duplicate sections or keys in the target section are ambiguous and refused.
func (d *ConfigDocument) SetSectionField(section, key, value string) error {
	validName := func(s string) bool {
		return s != "" && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "[]#;=\r\n\x00")
	}
	if !validName(section) || section == "Rule" || !validName(key) {
		return problem.New("value_invalid", "invalid section field")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return problem.New("value_has_invalid_characters", "invalid section field").In(section).On(key, value)
	}
	original := string(d.Bytes())
	// Refuse target fields beyond a disabled rule rather than creating duplicates.
	activeSection, afterDisabled := "", false
	for _, line := range documentLines(strings.TrimPrefix(original, d.prefix)) {
		name, disabled := documentHeader(line)
		if name != "" {
			if disabled {
				afterDisabled = true
			} else {
				activeSection = name
				afterDisabled = false
			}
			continue
		}
		value := strings.TrimSpace(line)
		if activeSection == section && afterDisabled && value != "" && !strings.HasPrefix(value, "#") && !strings.HasPrefix(value, ";") {
			return problem.New("section_ambiguous", "ambiguous section fields after disabled rule; use raw editing").In(section).At(key)
		}
	}
	text := strings.TrimPrefix(original, d.prefix)
	lines := documentLines(text)
	start, end, field := -1, len(lines), -1
	seen := map[string]bool{}
	inside := false
	for i, line := range lines {
		name, disabled := documentHeader(line)
		if name != "" {
			if inside {
				end = i
			}
			inside = name == section && !disabled
			if inside {
				if start >= 0 {
					return problem.New("section_duplicate", "duplicate section").In(section)
				}
				start = i
			}
			continue
		}
		if !inside {
			continue
		}
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		k, _, ok := strings.Cut(s, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return problem.New("syntax_invalid", "malformed or duplicate section field").In(section)
		}
		if seen[k] {
			return problem.New("option_duplicate", "malformed or duplicate section field").In(section).At(k)
		}
		seen[k] = true
		if k == key {
			field = i
		}
	}
	// Quote every edited value so leading/trailing whitespace and delimiters round-trip.
	replacement := strconv.Quote(value)
	eol := "\n"
	if strings.Contains(original, "\r\n") {
		eol = "\r\n"
	}
	if field >= 0 {
		line := lines[field]
		eq := strings.IndexByte(line, '=')
		right := line[eq+1:]
		ws := right[:len(right)-len(strings.TrimLeft(right, " \t"))]
		tail := right[len(strings.TrimRight(right, " \t\r\n")):]
		lines[field] = line[:eq+1] + ws + replacement + tail
	} else {
		addition := key + "=" + replacement + eol
		if start < 0 {
			end = len(lines)
			addition = "[" + section + "]" + eol + addition
		}
		if end > 0 && !strings.HasSuffix(lines[end-1], "\n") {
			addition = eol + addition
		}
		lines = append(lines, "")
		copy(lines[end+1:], lines[end:])
		lines[end] = addition
	}
	// Locate only the edited section after insertion, including disabled boundaries.
	text = strings.Join(lines, "")
	lines = documentLines(text)
	start, end = -1, len(lines)
	for i, line := range lines {
		name, disabled := documentHeader(line)
		if name == "" {
			continue
		}
		if start >= 0 {
			end = i
			break
		}
		if name == section && !disabled {
			start = i
		}
	}
	before := strings.Join(lines[:start], "")
	block := strings.Join(lines[start:end], "")
	after := strings.Join(lines[end:], "")
	next := ParseConfigDocument([]byte(d.prefix + before + documentGap(before, block, eol) + block + documentGap(block, after, eol) + after))
	*d = *next
	return nil
}

// FieldsJSON returns decoded non-rule values for visual controls. It does not
// validate runtime settings. Ambiguous fields refuse visual interpretation.
func (d *ConfigDocument) FieldsJSON() (string, error) {
	fields := map[string]string{}
	sections := map[string]bool{}
	section := ""
	for _, line := range documentLines(strings.TrimPrefix(string(d.Bytes()), d.prefix)) {
		name, disabled := documentHeader(line)
		if name != "" {
			if disabled {
				continue
			}
			section = name
			if name != "Rule" {
				if sections[name] {
					return "", problem.New("section_duplicate", "duplicate section").In(name)
				}
				sections[name] = true
			}
			continue
		}
		s := strings.TrimSpace(line)
		if section == "Rule" || s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		key, value, ok := strings.Cut(s, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || section == "" || key == "" {
			return "", problem.New("syntax_invalid", "malformed section field").In(section)
		}
		id := section + "/" + key
		if _, exists := fields[id]; exists {
			return "", problem.New("option_duplicate", "duplicate section field").In(section).At(key)
		}
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return "", problem.New("syntax_invalid", "invalid quoted section field").In(section).At(key)
			}
			value = decoded
		}
		fields[id] = value
	}
	b, err := json.Marshal(fields)
	return string(b), err
}
