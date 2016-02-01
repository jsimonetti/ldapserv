package debug

import "github.com/jsimonetti/ldapserv/ldap"

func (d *DebugBackend) Bind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	dump(r)
	res := ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform)
	w.Write(res)
}
