package ldapdn_test

import (
    "fmt"
    "github.com/vetinari/go-ldapdn"
    "sort"
    "testing"
)

func TestDNString(t *testing.T) {
    fmt.Printf("DNString: starting...\n")
    dn, _ := ldapdn.New("OU=Sales+CN=J. Smith,DC=example,DC=net")
    strdn := dn.String()
    if strdn != "ou=Sales+cn=J. Smith,dc=example,dc=net" {
        t.Errorf("Failed to stringify: %v\n", strdn)
    }
    fmt.Printf("DNString: -> %v\n", strdn)
    dn2, _ := ldapdn.New("CN=Lučić\\+Ma\\=><foo")
    if _, err := ldapdn.New(dn2.String()); err != nil {
        t.Errorf("Failed to parse stringified DN: %s", err)
    }
}

func TestCanonicalDN(t *testing.T) {
    dn := "ou=Sales+CN=J. Smith,  DC=example, DC=net"
    cdn, _ := ldapdn.CanonicalDN(dn)
    if cdn != "ou=Sales+cn=J. Smith,dc=example,dc=net" {
        t.Errorf("Canonical DN Failed: %s\n", cdn)
    }
}

func TestDNParent(t *testing.T) {
    fmt.Printf("DN Parent: starting...\n")
    dn, _ := ldapdn.New("OU=Sales+CN=J. Smith,DC=example,DC=net")
    parent := dn.Parent()
    if dn.String() != "ou=Sales+cn=J. Smith,dc=example,dc=net" {
        t.Errorf("original dn modified -> %s\n", dn)
    }
    if parent.String() != "dc=example,dc=net" {
        t.Errorf("wrong parent -> %s\n", parent)
    }
    fmt.Printf("DN Parent: %s -> %s\n", dn, parent)
}

func TestDNMove(t *testing.T) {
    fmt.Printf("DN Rename and Move: starting...\n")
    dn, _ := ldapdn.New("OU=Sales+CN=J. Smith,DC=example,DC=net")
    base, _ := ldapdn.New("OU=People,DC=example,DC=net")
    rdn, _ := ldapdn.New("cn=J. Smith")
    dn.Move(base)
    if dn.String() != "ou=Sales+cn=J. Smith,ou=People,dc=example,dc=net" {
        t.Errorf("Failed to move: %s\n", dn)
    }
    dn.Rename(rdn.RDNs[0])
    if dn.String() != "cn=J. Smith,ou=People,dc=example,dc=net" {
        t.Errorf("Failed to rename: %s\n", dn)
    }
    fmt.Printf("DN Rename and Move: %s\n", dn)
}

func TestDNEqual(t *testing.T) {
    dn1, _ := ldapdn.New("OU=people,DC=example,DC=org")
    dn2, _ := ldapdn.New("ou=People,dc=Example,dc=ORG")
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
    var dns []*ldapdn.DN
    dnStrings := []string{
        "ou=people,dc=example,dc=org",
        "uid=another,ou=people,dc=example,dc=org",
        "uid=another+cn=one,ou=people,dc=example,dc=org",
        "dc=example,dc=org",
        "uid=someone,ou=people,dc=example,dc=org",
        "ou=robots,dc=example,dc=org",
        "uid=someone,ou=robots,dc=example,dc=org",
    }

    for _, s := range dnStrings {
        dn, _ := ldapdn.New(s)
        dns = append(dns, dn)
    }
    sort.Sort(ldapdn.DNs(dns))
    for _, dn := range dns {
        fmt.Printf("DN: %s\n", dn.String())
    }
    if dns[len(dns)-1].String() != "dc=example,dc=org" {
        t.Errorf("DN dc=example,dc=org is not last")
    }
    if dns[0].String() != "uid=another,ou=people,dc=example,dc=org" {
        t.Errorf("DN uid=another,ou=people,dc=example,dc=org is not first")
    }
}

func TestDNClone(t *testing.T) {
    dn, _ := ldapdn.New("uid=someone,ou=people,dc=example,dc=org")
    newrdn, _ := ldapdn.New("uid=foobar")
    clone := dn.Clone()
    dn.Rename(newrdn.FirstRDN())
    fmt.Printf("RENAMED=%s, CLONE=%s\n", dn, clone)
    if clone.RDN() == dn.RDN() {
        t.Errorf("Clone Failed: %s\n", clone.RDN())
    }
}
