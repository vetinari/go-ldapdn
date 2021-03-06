package ldapdn

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func TestDNString(t *testing.T) {
	fmt.Printf("DNString: starting...\n")
	dn, _ := New("OU=Sales+CN=J. Smith,DC=example,DC=net")
	strdn := dn.String()
	if strdn != "cn=J. Smith+ou=Sales,dc=example,dc=net" {
		t.Errorf("Failed to stringify: %v\n", strdn)
	}
	fmt.Printf("DNString: -> %v\n", strdn)
	dn2, _ := New("CN=Lučić\\+Ma\\=><foo")
	if _, err := New(dn2.String()); err != nil {
		t.Errorf("Failed to parse stringified DN: %s", err)
	}
}

func TestRDNString(t *testing.T) {
	dn, _ := New("cn=J. Smith+ou=Sales")
	dn2, _ := New("ou=Sales+cn=J. Smith")
	strdn := dn.FirstRDN().String()
	if strdn != "cn=J. Smith+ou=Sales" {
		t.Errorf("Failed to stringify: %v\n", strdn)
	}
	if dn2.FirstRDN().String() != strdn {
		t.Errorf("both RDNs not equal: %v\n", strdn)
	}
}

func TestNewRDN(t *testing.T) {
	rdn, err := NewRDN("ou", "Sales", "cn", "J. Smith")
	if err != nil {
		t.Errorf("failed to build RDN: %s", err)
	}
	if rdn.String() != "cn=J. Smith+ou=Sales" {
		t.Errorf("Failed to stringify RDN: %v\n", rdn)
	}
}

func TestDNInvalidString(t *testing.T) {
	dn, err := New("uid=foo,bar,dc=example,dc=org")
	if err != nil {
		t.Errorf("did not fail to parse invalid DN %s", dn)
	}
}

func TestEscapeValue(t *testing.T) {
	str := "test\atest"
	res := escapeValue(str)
	fmt.Printf("STR=%v\n", res)
	if res != `test\07test` {
		t.Errorf("did not escape \\a correctly")
	}
}

func TestCanonicalDN(t *testing.T) {
	dn := "ou=Sales+CN=J. Smith,  DC=example, DC=net"
	cdn, _ := CanonicalDN(dn)
	if cdn != "cn=J. Smith+ou=Sales,dc=example,dc=net" {
		t.Errorf("Canonical DN Failed: %s\n", cdn)
	}
}

func TestCanonicalDNFolded(t *testing.T) {
	dn := "ou=Sales+CN=J. Smith,  DC=example, DC=net"
	cdn, _ := CanonicalDN(dn, true)
	if cdn != "cn=j. smith+ou=sales,dc=example,dc=net" {
		t.Errorf("Canonical DN Folded Failed: %s\n", cdn)
	}
}

func TestDNParent(t *testing.T) {
	fmt.Printf("DN Parent: starting...\n")
	dn, _ := New("OU=Sales+CN=J. Smith,DC=example,DC=net")
	parent := dn.Parent()
	if dn.String() != "cn=J. Smith+ou=Sales,dc=example,dc=net" {
		t.Errorf("original dn modified -> %s\n", dn)
	}
	if parent.String() != "dc=example,dc=net" {
		t.Errorf("wrong parent -> %s\n", parent)
	}
	fmt.Printf("DN Parent: %s -> %s\n", dn, parent)
	dn = &DN{}
	parent = dn.Parent()
	if parent.String() != dn.String() {
		t.Errorf("Parent() is not equal DN with empty DN")
	}
}

func TestDNMove(t *testing.T) {
	fmt.Printf("DN Rename and Move: starting...\n")
	dn, _ := New("OU=Sales+CN=J. Smith,DC=example,DC=net")
	base, _ := New("OU=People,DC=example,DC=net")
	rdn, _ := New("cn=J. Smith")
	dn.Move(base)
	if dn.String() != "cn=J. Smith+ou=Sales,ou=People,dc=example,dc=net" {
		t.Errorf("Failed to move: %s\n", dn)
	}
	dn.Rename(rdn.RDNs[0])
	if dn.String() != "cn=J. Smith,ou=People,dc=example,dc=net" {
		t.Errorf("Failed to rename: %s\n", dn)
	}
	fmt.Printf("DN Rename and Move: %s\n", dn)
}

func TestDNEqual(t *testing.T) {
	dn1, _ := New("OU=people,DC=example,DC=org")
	dn2, _ := New("ou=People,dc=Example,dc=ORG")
	dn1.CaseFold = true
	dn2.CaseFold = true
	if !dn1.Equal(dn2) {
		t.Errorf("both dns not equal")
	}
	dn1.CaseFold = false
	dn2.CaseFold = false
	if dn1.Equal(dn2) {
		t.Errorf("both dns equal with ldap.RDNCompareFold = false")
	}
}

func TestDNSort(t *testing.T) {
	var dns []*DN
	dnSorted := []string{
		"cn=ReadOnly,ou=Roles,ou=acc1,ou=aws,dc=example,dc=org",
		"cn=PowerUser,ou=Roles,ou=acc1,ou=aws,dc=example,dc=org",
		"cn=Administrator,ou=Roles,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=Roles,ou=acc1,ou=aws,dc=example,dc=org",
		"cn=eu-central-1,ou=odd,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=odd,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"cn=eu-central-1b,ou=nat,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"cn=eu-central-1a,ou=nat,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=nat,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=acc1,ou=aws,dc=example,dc=org",
	}

	dnUnsorted := []string{
		"cn=eu-central-1b,ou=nat,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"cn=PowerUser,ou=Roles,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=Roles,ou=acc1,ou=aws,dc=example,dc=org",
		"cn=eu-central-1,ou=odd,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"cn=ReadOnly,ou=Roles,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=acc1,ou=aws,dc=example,dc=org",
		"cn=Administrator,ou=Roles,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=odd,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"cn=eu-central-1a,ou=nat,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
		"ou=nat,ou=IPs,ou=acc1,ou=aws,dc=example,dc=org",
	}

	for _, s := range dnUnsorted {
		dn, _ := New(s)
		dns = append(dns, dn)
	}
	sort.Sort(DNS(dns))
	var out []string
	for _, dn := range dns {
		out = append(out, dn.String())
	}
	if !reflect.DeepEqual(out, dnSorted) {
		t.Errorf("failed to sort: %v", out)
	}
}

func TestDNClone(t *testing.T) {
	dn, _ := New("uid=someone,ou=people,dc=example,dc=org")
	newrdn, _ := New("uid=foobar")
	clone := dn.Clone()
	dn.Rename(newrdn.FirstRDN())
	fmt.Printf("RENAMED=%s, CLONE=%s\n", dn, clone)
	if clone.RDN() == dn.RDN() {
		t.Errorf("Clone Failed: %s\n", clone.RDN())
	}
}

func TestDNPretty(t *testing.T) {
	dn, _ := New("cn=group,ou=some,ou=apps,dc=example,dc=org")
	base, _ := New("dc=example,dc=org")
	p := dn.Pretty(base, "/", nil)
	if p != "Apps/Some/Group" {
		t.Errorf("Petty failed: %s\n", p)
	}
	p = dn.Pretty(base, "", nil)
	if p != "Apps/Some/Group" {
		t.Errorf("Petty failed: %s\n", p)
	}

}

func TestIsSubordinate(t *testing.T) {
	dn, _ := New("cn=group,ou=some,ou=apps,dc=example,dc=org")
	if dn.IsSubordinate(nil) {
		t.Errorf("did not fail IsSubordinate() on nil parent")
	}
	base, _ := New("dc=example,dc=org")
	if !dn.IsSubordinate(base) {
		t.Errorf("fail IsSubordinate() on parent")
	}

	notBase, _ := New("dc=example,dc=com")
	if dn.IsSubordinate(notBase) {
		t.Errorf("did not fail IsSubordinate() on non parent")
	}
}

func TestReverse(t *testing.T) {
	dn, _ := New("cn=group,ou=some,ou=apps,dc=example,dc=org")
	rev := dn.Reverse()
	if rev.String() != "dc=org,dc=example,ou=apps,ou=some,cn=group" {
		t.Errorf("failed to reverse DN: %s", rev)
	}
}

func TestRDNAppend(t *testing.T) {
	dn, _ := New("cn=group,ou=some,ou=apps,dc=example,dc=org")
	rdn := dn.FirstRDN()
	if !rdn.Append(dn.Parent()).Equal(dn) {
		t.Errorf("append RDN failed...")
	}
}
