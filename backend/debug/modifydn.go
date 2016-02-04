package debug

import "github.com/jsimonetti/ldapserv/ldap"

func (d *DebugBackend) ModifyDN(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyDNRequest()
	dump(r)
	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
