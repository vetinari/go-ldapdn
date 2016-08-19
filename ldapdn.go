package ldapdn

import (
	enchex "encoding/hex"
	"errors"
	"strings"

	"gopkg.in/ldap.v2"
)

// ErrDNNotSubordinate is returned when the DN is not a subordinate of
// the DN to be stripped
var ErrDNNotSubordinate = errors.New("Not a subordinate")

// DN is a DN. When CaseFold is true, the RDN values are compared case insensitive
type DN struct {
	RDNs     []*RelativeDN
	CaseFold bool
}

// RelativeDN is part of a DN
type RelativeDN struct {
	*ldap.RelativeDN
}

// CanonicalDN returns the canonical DN form of a DN, i.e.:
// all attributes are lowercased and have spaces removed,
// all BER encoding converted,
// all necessary characters escaped.
// this is a convenience function around New() and String()
func CanonicalDN(dn string) (string, error) {
	ldn, err := New(dn)
	if err != nil {
		return "", err
	}
	return ldn.String(), nil
}

// New creates a new DN from a string DN.
func New(dn string) (*DN, error) {
	ldn, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, err
	}
	var rdns []*RelativeDN
	for _, r := range ldn.RDNs {
		for _, av := range r.Attributes {
			av.Type = strings.TrimSpace(av.Type)
		}
		rdns = append(rdns, &RelativeDN{r})
	}
	return &DN{RDNs: rdns, CaseFold: false}, nil
}

// String returns the stringified version of a *DN, the RDN values are escaped
func (dn *DN) String() string {
	var rdns []string
	for _, r := range dn.RDNs {
		rdns = append(rdns, r.String())
	}
	return strings.Join(rdns, ",")
}

func escapeValue(value string) (escaped string) {
	for _, r := range value {
		switch r {
		case ',', '+', '"', '\\', '<', '>', ';', '#', '=':
			escaped += "\\" + string(r)
		default:
			if uint(r) < 32 {
				escaped += "\\" + enchex.EncodeToString([]byte(string(r)))
			} else {
				escaped += string(r)
			}
		}
	}
	return
}

// Pretty returns a "pretty" version of a DN:
// the base is stripped and all RDN values are joined by the separator
// "sep", by default a "/".
// The conv func is used to transform the RDN value, default is
// strings.Title.
func (dn *DN) Pretty(base *DN, sep string, conv func(string) string) string {
	if sep == "" {
		sep = "/"
	}
	if conv == nil {
		conv = strings.Title
	}

	var parts []string
	_ = dn.Strip(base)
	rdn := dn.RDN()
	for rdn != "" {
		parts = append(parts, rdn)
		dn = dn.Parent()
		rdn = dn.RDN()
	}
	var rev []string
	for i := len(parts) - 1; i >= 0; i-- {
		rev = append(rev, conv(parts[i]))
	}
	return strings.Join(rev, sep)
}

// Equal checks if all RDNs of both DNs are equal
func (dn *DN) Equal(other *DN) bool {
	if len(dn.RDNs) != len(other.RDNs) {
		return false
	}
	for i, rdn := range dn.RDNs {
		if !rdn.Equal(other.RDNs[i], dn.CaseFold) {
			return false
		}
	}
	return true
}

// Equal checks if all types and values of both RDNs are equal
func (r *RelativeDN) Equal(o *RelativeDN, fold bool) bool {
	if len(r.Attributes) != len(o.Attributes) {
		return false
	}
	for i, av := range r.Attributes {
		if strings.ToLower(av.Type) != strings.ToLower(o.Attributes[i].Type) {
			return false
		}
		if fold {
			if !strings.EqualFold(av.Value, o.Attributes[i].Value) {
				return false
			}
		} else {
			if av.Value != o.Attributes[i].Value {
				return false
			}
		}
	}
	return true
}

// IsSubordinate returns true if the "other" DN is a parent of "dn"
func (dn *DN) IsSubordinate(other *DN) bool {
	if other == nil {
		return false
	}
	off := len(dn.RDNs) - len(other.RDNs)
	if off <= 0 {
		return false
	}
	for i, rdn := range other.RDNs {
		if !rdn.Equal(dn.RDNs[i+off], dn.CaseFold) {
			return false
		}
	}
	return true
}

// Append appends the "other" DN to the "dn", e.g.
//
//  dn, err := ldapdn.New("CN=Someone")
//  base, err := ldapdn.New("ou=people,dc=example,dc=org")
//  dn.Append(base) -> "cn=Someone,ou=people,dc=example,dc=org"
func (dn *DN) Append(other *DN) {
	dn.RDNs = append(dn.RDNs, other.RDNs...)
}

// Strip removes the "other" DN from the "dn", e.g.
//
//  dn, err := ldapdn.New("cn=Someone,ou=people,dc=example,dc=org")
//  base, err := ldapdn.New("ou=people,dc=example,dc=org")
//  dn.Strip(base) -> "cn=Someone"
//
// Note: the "other" DN must be a parent of the "dn"
func (dn *DN) Strip(base *DN) error {
	if !dn.IsSubordinate(base) {
		return ErrDNNotSubordinate
	}
	dn.RDNs = dn.RDNs[0 : len(dn.RDNs)-len(base.RDNs)]
	return nil
}

// Rename changes the first RDN of DN to the given one
func (dn *DN) Rename(rdn *RelativeDN) {
	dn.RDNs[0] = rdn
}

// Move moves the first RDN to the new base
func (dn *DN) Move(newBase *DN) {
	dn.RDNs = dn.RDNs[:1]
	dn.Append(newBase)
}

// RDN Returns the value of the first RDN, e.g.
//  dn, err := ldapdn.New("uid=someone,ou=people,dc=example,dc=org")
//  dn.RDN() -> "someone"
func (dn *DN) RDN() string {
	if len(dn.RDNs) == 0 || len(dn.RDNs[0].Attributes) == 0 {
		return ""
	}
	return dn.RDNs[0].Attributes[0].Value
}

// FirstRDN returns the first RDN, e.g.
//
//  dn, err := ldapdn.New("uid=someone,ou=people,dc=example,dc=org")
//  dn2, err := ldapdn.New("uid=foo")
//  dn.Move(dn2.FirstRDN())
func (dn *DN) FirstRDN() *RelativeDN {
	if len(dn.RDNs) == 0 {
		return nil
	}
	return dn.RDNs[0]
}

// Parent returns the parent of the "dn" as a cloned *DN
func (dn *DN) Parent() *DN {
	c := dn.Clone()
	if len(c.RDNs) > 0 {
		c.RDNs = c.RDNs[1:]
		return c
	}
	c.RDNs = []*RelativeDN{}
	return c
}

// Clone returns a copy of the DN
func (dn *DN) Clone() *DN {
	c := &DN{}
	for _, r := range dn.RDNs {
		rc := &RelativeDN{&ldap.RelativeDN{}}
		for _, tv := range r.Attributes {
			rc.Attributes = append(rc.Attributes, &ldap.AttributeTypeAndValue{Type: tv.Type, Value: tv.Value})
		}
		c.RDNs = append(c.RDNs, rc)
	}
	return c
}

// DNS is used for sorting DNs:
// (sometimes golint is annoyingly wrong, should be DNs...)
//   all := []*ldap.DN{dn1, dn2, dn3, dn4}
//   sort.Sort(DNs(all))
//   for _, dn := range all {
//      println(dn.String())
//   }
//
// The result order from deepest part in tree upwards, so you could
// easily search for all dns in a base, sort them and then remove
// every DN in that order to remove the tree (including the search base)
type DNS []*DN

func (d DNS) Len() int {
	return len(([]*DN)(d))
}

func (d DNS) Swap(i, j int) {
	([]*DN)(d)[i], ([]*DN)(d)[j] = ([]*DN)(d)[j], ([]*DN)(d)[i]
}

func (d DNS) Less(i, j int) bool {
	return ([]*DN)(d)[i].IsSubordinate(([]*DN)(d)[j])
}

// String returns the stringified version of an RDN
func (r *RelativeDN) String() string {
	var parts []string
	for _, a := range r.Attributes {
		parts = append(parts, strings.ToLower(a.Type)+"="+escapeValue(a.Value))
	}
	return strings.Join(parts, "+")
}
