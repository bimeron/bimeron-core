package accesskey

import "reflect"

// Equivalent reports whether two profiles connect to the same upstream with the
// same settings. It ignores the display name and whether XHTTP options came
// from one XHTTPExtra value or separate options, and treats an omitted Trojan
// transport as tcp, which is how Trojan dials it.
func Equivalent(a, b Profile) bool {
	return reflect.DeepEqual(comparisonForm(a), comparisonForm(b))
}

func comparisonForm(p Profile) Profile {
	p.Name = ""
	if p.Trojan.Network == "" {
		p.Trojan.Network = "tcp"
	}
	p.VLESS.XHTTPOptions = unseparated(p.VLESS.XHTTPOptions)
	p.VMess.XHTTPOptions = unseparated(p.VMess.XHTTPOptions)
	return p
}

func unseparated(o *XHTTPOptions) *XHTTPOptions {
	if o == nil {
		return nil
	}
	c := *o
	c.separate = false
	return &c
}
