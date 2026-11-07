// Package problem defines located, catalog-coded validation failures.
//
// See docs/ERRORS.MD. An Error never carries secret values: Value reports only
// whether a field was set, and Args must contain safe placeholder values.
package problem

import (
	"errors"
	"strconv"
)

// Value reports whether a field had a non-empty value.
type Value string

const (
	Present Value = "present"
	Absent  Value = "absent"
)

// Unclassified is the code of a failure the core could not classify.
const Unclassified = "unclassified"

// Error is a structured validation problem. Error() returns Message, the
// historical English text, so existing callers and CLI output are unchanged.
type Error struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Section string            `json:"section,omitempty"`
	Field   string            `json:"field,omitempty"`
	Related []string          `json:"related,omitempty"`
	Source  string            `json:"source,omitempty"`
	Rule    int               `json:"rule,omitempty"`
	Line    int               `json:"line,omitempty"`
	Value   Value             `json:"value,omitempty"`
	Args    map[string]string `json:"args,omitempty"`
	cause   error
}

// New returns a problem with a catalog code and the English message.
func New(code, message string) *Error { return &Error{Code: code, Message: message} }

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.cause }

// In sets the profile section.
func (e *Error) In(section string) *Error { e.Section = section; return e }

// On sets the canonical field and records only whether value was non-empty.
func (e *Error) On(field, value string) *Error {
	e.Field = field
	e.Value = Absent
	if value != "" {
		e.Value = Present
	}
	return e
}

// At sets the canonical field without a value state.
func (e *Error) At(field string) *Error { e.Field = field; return e }

// Also lists other fields that take part in a combination rule.
func (e *Error) Also(fields ...string) *Error { e.Related = append(e.Related, fields...); return e }

// From records the URI or key option that held the value.
func (e *Error) From(source string) *Error { e.Source = source; return e }

// AtRule sets the one-based rule index.
func (e *Error) AtRule(rule int) *Error { e.Rule = rule; return e }

// AtLine sets the one-based profile line.
func (e *Error) AtLine(line int) *Error { e.Line = line; return e }

// Arg adds a safe placeholder value. Never pass secrets or user input.
func (e *Error) Arg(name, value string) *Error {
	if e.Args == nil {
		e.Args = map[string]string{}
	}
	e.Args[name] = value
	return e
}

// ArgInt adds a numeric placeholder value.
func (e *Error) ArgInt(name string, value int) *Error { return e.Arg(name, strconv.Itoa(value)) }

// Wrap keeps cause for errors.Is/As without exposing its text.
func (e *Error) Wrap(cause error) *Error { e.cause = cause; return e }

// Provider is implemented by typed errors that can describe themselves.
type Provider interface{ Problem() *Error }

// As returns the problem carried by err, if any.
func As(err error) (*Error, bool) {
	var p *Error
	if errors.As(err, &p) {
		return p, true
	}
	var provider Provider
	if errors.As(err, &provider) {
		if p = provider.Problem(); p != nil {
			return p, true
		}
	}
	return nil, false
}

// Of converts err into a problem. Unknown errors become Unclassified with the
// original text as message; callers must only pass errors whose text is safe.
func Of(err error) *Error {
	if err == nil {
		return nil
	}
	if p, ok := As(err); ok {
		return p
	}
	return New(Unclassified, err.Error()).Wrap(err)
}

// List returns the transport representation: an empty list for nil.
func List(err error) []*Error {
	if err == nil {
		return []*Error{}
	}
	return []*Error{Of(err)}
}
