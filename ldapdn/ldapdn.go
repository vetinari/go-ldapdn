
package ldapdn

import (
        "regexp"
        "fmt"
        "errors"
        "encoding/hex"
        "strings"
        "sort"
    )

var pair_re string = `\\(?:[\\"+,;<> #=]|[0-9A-F]{2})`
var attr_re string = `((?i)[A-Z][-A-Z0-9]*|(?:oid\.)?\d+(?:\.\d+)*)`
var re = regexp.MustCompile(`(?:\s*` + attr_re +
            `\s*=[ ]*((?:(?:[^\x00 "\#+,;<>\\\x80-\xBF]|` + pair_re +
            `)(?:(?:[^\x00"+,;<>\\]|` + pair_re + `)*(?:[^\x00 "+,;<>\\]|` + pair_re +
            `))?)?|\#(?:[0-9a-fA-F]{2})+|"(?:[^\\"]+|` + pair_re +
            `)*")[ ]*(?:([;,+])\s*|$))\s*`)
var oid = regexp.MustCompile(`^(?i)oid\.`)

var escaped = regexp.MustCompile(`\\([\\ ",=+<>#;]|[0-9a-fA-F]{2})`)
// regex for matching "insecure" charachters which should be replaced
var insecure = regexp.MustCompile(`([\x00-\x1f\/\\",=+<>#;])`)

// DN - struct to hold the exploded DN
type DN struct {
    dn []map[string]string
}

// New() - create a new DN from a string
// returns:
//  new DN
//  error
func New(dn_str string) (*DN, error) {
    self := new(DN)
    err := self.explode(dn_str)
    if err != nil {
        return nil, err
    }
    return self, nil
}

func (self *DN) explode(dn_str string) error {
    if dn_str == "" {
        return nil
    }
    res := re.FindAllStringSubmatch(dn_str, -1)
    if len(res) == 0 {
        return errors.New(fmt.Sprintf("Could not explode DN '%s'", dn_str))
    }

    var dn []map[string]string
    var rdn = make(map[string]string)
    for _, part := range res {
        attr := part[1]
        val  := part[2]
        sep  := part[3]

        attr = oid.ReplaceAllString(attr, "")

        if val[0] == '#' {
            // decode hex-encoded BER value
            val = val[1:]
            // val_b, err := hex.DecodeString(val)
            val_b, _ := hex.DecodeString(val)
            val = string(val_b)
        } else {
            if val[0] == '"' && val[len(val)] == '"' {
                // remove quotes
                val = val[1:len(val)-1]
            }
            val = escaped.ReplaceAllStringFunc(val, unescape)
        }
        rdn[attr] = val
        if sep != "+" {
            dn = append(dn, rdn)
            rdn = make(map[string]string)
        }
    }
    self.dn = dn
    // fmt.Printf("SELF=> %q\n", self)
    return nil
}

// CanonicalDN()
// input: DN as string
// returns: canonical form of the given DN
func CanonicalDN(dn_str string) (string, error) {
    dn, err := New(dn_str)
    if err != nil {
        return "", err
    }
    return dn.canonicalize(), nil
}

func (self *DN) canonicalize() (string) {
    var dn []string
    for _, rdn := range self.dn {
        var parts []string
        for key, val := range rdn {
            val = insecure.ReplaceAllStringFunc(val, escape)
            parts = append(parts, key + "=" + val)
        }
        dn = append(dn, strings.Join(parts, "+"))
    }
    return strings.Join(dn, ",")
}

func escape(s string) (string) {
    return fmt.Sprintf("\\%02x", int(s[0]))
}

// String()
//  returns:
//   the canonical DN as string
func (self *DN) String() (string) {
    return self.canonicalize()
}

func unescape(s string) (string) {
    s = s[1:]
    if len(s) == 1 {
        return s
    }
    // s_b, err := hex.DecodeString(s)
    s_b, _ := hex.DecodeString(s)
    return string(s_b)
}

// Clone()
//  returns:
//   - a clone of the DN
func (self *DN) Clone() (*DN) {
    return self.clone()
}

func (self *DN) clone() (*DN) {
    c := *self
    return &c
}

// Parent()
// returns:
//   the parent of the DN from a cloned instance
func (self *DN) Parent() (*DN) {
    c := self.clone()
    if len(c.dn) <= 1 {
        c.dn = []map[string]string{}
    } else {
        c.dn = c.dn[1:]
    }
    return c
}

// RDN()
// return the first (i.e. the one deepest in the tree) as
// string. With a true argument, the attribute will be present (e.g.
// CN=Someone). With a false value only the attribute ("CN=Someone,DC=example,DC=org
// -> "Someone").
func (self *DN) RDN(key bool) (string) {
    if len(self.dn) == 0 {
        return ""
    }
    if key {
        c := self.clone()
        c.dn = c.dn[0:0]
        return c.String()
    }
    var rdn []string
    for _, val := range self.dn[0] {
        rdn = append(rdn, val)
    }
    return strings.Join(rdn, "+")
}

// Equal()
//  checks if two DNs are equal
// returns: bool
func (self *DN) Equal(other *DN) (bool) {
    if len(self.dn) != len(other.dn) {
        return false
    }
    return compare(self.dn, other.dn)
}

// Strip()
// removes the given DN from the end, i.e.
//  with DN "CN=Someone,DC=example,DC=org" stripped by
//  a dn of "DC=example,DC=org"
//  results in "CN=Someone" (see RDN() if you just need
//  the first RDN as string
func (self *DN) Strip(other *DN) (*DN) {
    if !self.IsSubordinate(other) {
        empty, _ := New("")
        return empty
    }
    c := self.clone()
    c.dn = c.dn[:len(c.dn) - len(other.dn)]
    return c
}

// Append()
// appends the given DN to the current one
// returns:
//  a cloned DN of the current one with the given appended,
// i.e.:
//    dn := ldapdn.New("uid=foo,ou=bar")
//    app := ldapdn.New("dc=example,dc=org")
//    dn.Append(app).String => "uid=foo,ou=bar,dc=example,dc=org"
func (self *DN) Append(other *DN) (*DN) {
    c := self.clone()
    for _, rdn := range other.dn {
        c.dn = append(c.dn, rdn)
    }
    return c
}

func rdn_equal(l map[string]string, r map[string]string) (bool) {
    if len(l) != len(r) {
        return false
    }
    var keys []string
    for k := range l {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    for _, k := range keys {
        if r[k] == "" {
            return false
        }
        if l[k] != r[k] {
            return false
        }
    }
    return true
}

func compare(l []map[string]string, r []map[string]string) (bool) {
    for i := range l {
        if !rdn_equal(l[i], r[i]) {
            return false
        }
    }
    return true
}

func reverse (f []map[string]string) (r []map[string]string) {
    var o []map[string]string
    for i := range f {
        i := i
        defer func() { o = append(o, f[i]) }()
    }
    return
}

// IsSubordinate()
//  checks if the DN a subordinate of the given one
// returns:
//  bool
func (self *DN) IsSubordinate(other *DN) (bool) {
    if len(self.dn) <= len(other.dn) {
        return false
    }
    return compare(reverse(self.dn), reverse(other.dn))
}

// This implements the sort interface so we can sort DNs:
//
// NOTE: this sorts down from the top of the tree
//    import (
//       "sort"
//       "ldapdn"
//       "fmt"
//    )
//
//    func main() {
//        var s ldapdn.DNSlice
//        s = append(s, ldapdn.New("UID=username,OU=users,DC=example,DC=org"),
//                      ldapdn.New("OU=users,DC=example,DC=org"),
//                      ldapdn.New("DC=example,DC=org"),
//                      ldapdn.New("OU=disabled,DC=example,DC=org"),
//                      ldapdn.New("UID=someone,OU=users,DC=example,DC=org"),
//                  )
//        sort.Sort(s)
//        for _, d := range s {
//            fmt.Printf("%s\n", d.String())
//        }
//    }
//  ------------------
//  DC=example,DC=org
//  OU=users,DC=example,DC=org
//  OU=disabled,DC=example,DC=org
//  UID=username,OU=users,DC=example,DC=org
//  UID=someone,OU=users,DC=example,DC=org
type DNSlice []*DN
func (d DNSlice) Len() int { return len(d) }
func (d DNSlice) Less(i, j int) (bool) { return d[j].IsSubordinate(d[i]) }
func (d DNSlice) Swap(i, j int) { d[i], d[j] = d[j], d[i] }

// END
// vim: ts=4 sw=4 expandtab syn=go
