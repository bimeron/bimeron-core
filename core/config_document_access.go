package core

import (
	"slices"
	"strconv"
	"strings"

	"bimeron/internal/config"
	"bimeron/internal/problem"
)

// ConvertAccess replaces the [AccessKey] source with the equivalent explicit
// parameters (toFields) or share URI. Only the replaced option lines change;
// the first one becomes the new options, others are removed. Core verifies the
// runtime profile is unchanged; any failure leaves the document unchanged.
func (d *ConfigDocument) ConvertAccess(toFields bool) error {
	text := strings.TrimPrefix(string(d.Bytes()), d.prefix)
	lines := documentLines(text)
	start, end := -1, len(lines)
	inside, afterDisabled := false, false
	for i, line := range lines {
		name, disabled := documentHeader(line)
		if name != "" {
			if inside && end == len(lines) {
				end = i
			}
			if disabled {
				afterDisabled = inside || afterDisabled
				continue
			}
			inside = name == "AccessKey"
			if inside {
				if start >= 0 {
					return problem.New("section_duplicate", "duplicate section").In("AccessKey")
				}
				start, end = i, len(lines)
			}
			afterDisabled = false
			continue
		}
		s := strings.TrimSpace(line)
		if inside && afterDisabled && s != "" && !strings.HasPrefix(s, "#") && !strings.HasPrefix(s, ";") {
			return problem.New("section_ambiguous", "ambiguous section fields after disabled rule; use raw editing").In("AccessKey")
		}
	}
	if start < 0 {
		return problem.New("access_conversion_unsupported", "[AccessKey] source cannot be converted").In("AccessKey")
	}
	options := map[string]string{}
	at := map[string]int{}
	for i := start + 1; i < end; i++ {
		s := strings.TrimSpace(lines[i])
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		key, value, ok := strings.Cut(s, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" {
			return problem.New("syntax_invalid", "malformed section field").In("AccessKey")
		}
		if _, seen := at[key]; seen {
			return problem.New("option_duplicate", "duplicate section field").In("AccessKey").At(key)
		}
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return problem.New("syntax_invalid", "invalid quoted section field").In("AccessKey").At(key)
			}
			value = decoded
		}
		options[key], at[key] = value, i
	}
	conv, err := config.ConvertAccess(options, toFields)
	if err != nil {
		return err
	}
	eol := documentEOL(text)
	first := end
	for _, key := range conv.Remove {
		if i, ok := at[key]; ok && i < first {
			first = i
		}
	}
	var b strings.Builder
	for i, line := range lines {
		if i == first {
			for j, option := range conv.Add {
				b.WriteString(option.Key + " = " + optionValue(option.Value))
				if j < len(conv.Add)-1 || strings.HasSuffix(line, "\n") {
					b.WriteString(eol)
				}
			}
		}
		if i > start && i < end && slices.ContainsFunc(conv.Remove, func(key string) bool { return at[key] == i }) {
			continue
		}
		b.WriteString(line)
	}
	*d = *ParseConfigDocument([]byte(d.prefix + b.String()))
	return nil
}

// optionValue quotes values that a bare option line would not preserve.
func optionValue(value string) string {
	if value != strings.TrimSpace(value) || strings.HasPrefix(value, `"`) || strings.ContainsAny(value, "\r\n\x00") {
		return strconv.Quote(value)
	}
	return value
}
