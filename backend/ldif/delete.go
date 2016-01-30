package ldif

import (
	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

func (l *LdifBackend) Delete(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetDeleteRequest()
	l.Log.Debug("Deleting entry", log.Ctx{"entry": r})
	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
