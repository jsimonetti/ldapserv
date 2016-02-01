package debug

import "github.com/jsimonetti/ldapserv/ldap"

func (d *DebugBackend) Search(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	dump(r)
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
