package debug

import "github.com/jsimonetti/ldapserv/ldap"

func (d *DebugBackend) Extended(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	dump(r)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
