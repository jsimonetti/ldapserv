package main

import ldap "github.com/jsimonetti/ldapserver"

func handleBind(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	result := backend.Bind(r)
	switch result {
	case ldap.LDAPResultInvalidCredentials:
		res.SetDiagnosticMessage("invalid credentials")
	case ldap.LDAPResultUnwillingToPerform:
		res.SetDiagnosticMessage("Authentication choice not supported")
	}
	res.SetResultCode(result)
	w.Write(res)
}
