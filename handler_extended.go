package main

import (
	ldap "github.com/jsimonetti/ldapserver"
	log "gopkg.in/inconshreveable/log15.v2"
)

func handleExtended(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	r := m.GetExtendedRequest()
	logger.Debug("Extended request received", log.Ctx{"name": r.RequestName(), "value": r.RequestValue()})
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
