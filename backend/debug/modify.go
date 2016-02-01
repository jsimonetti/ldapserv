package debug

import "github.com/jsimonetti/ldapserv/ldap"

func (d *DebugBackend) Modify(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyRequest()
	dump(r)
	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
