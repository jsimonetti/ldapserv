package main

import ldap "github.com/jsimonetti/ldapserver"

func handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
