package debug

import "github.com/jsimonetti/ldapserv/ldap"

func (d *DebugBackend) Delete(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetDeleteRequest()
	dump(r)
	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
