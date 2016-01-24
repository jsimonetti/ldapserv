package main

import "github.com/jsimonetti/ldapserv/ldap"

func handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
