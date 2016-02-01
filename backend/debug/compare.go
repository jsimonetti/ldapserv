package debug

import "github.com/jsimonetti/ldapserv/ldap"

func (d *DebugBackend) Compare(w ldap.ResponseWriter, m *ldap.Message) {
	dump(m)
	res := ldap.NewCompareResponse(ldap.LDAPResultCompareTrue)
	w.Write(res)
}
