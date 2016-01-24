package main

import ldap "github.com/jsimonetti/ldapserver"

func handleDefaultBind(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	res := ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("No backend found")
	w.Write(res)
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials)

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

func handleDefaultSearch(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultUnwillingToPerform)
	w.Write(res)
}
func handleSearch(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	r := m.GetSearchRequest()
	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		logger.Debug("Leaving handleSearch...")
		return
	default:
	}

	entries, result := backend.Search(r)

	for i := 0; i < len(entries); i++ {
		w.Write(entries[i])
	}

	res := ldap.NewSearchResultDoneResponse(result)
	w.Write(res)
}
