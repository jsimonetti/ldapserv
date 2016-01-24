package main

import (
	ldap "github.com/jsimonetti/ldapserver"
	log "gopkg.in/inconshreveable/log15.v2"
)

func handleDelete(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	r := m.GetDeleteRequest()
	logger.Debug("Deleting entry", log.Ctx{"entry": r})
	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
