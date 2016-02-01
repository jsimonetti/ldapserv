package debug

import "github.com/jsimonetti/ldapserv/ldap"

func (d *DebugBackend) Add(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAddRequest()
	dump(r)
	res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
	w.Write(res)
}
