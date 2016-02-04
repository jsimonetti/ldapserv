package ldif

import "github.com/jsimonetti/ldapserv/ldap"

func (l *LdifBackend) ModifyDN(w ldap.ResponseWriter, m *ldap.Message) {
	//r := m.GetModifyDNRequest()
	l.Log.Debug("ModifyDN entry")
	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
