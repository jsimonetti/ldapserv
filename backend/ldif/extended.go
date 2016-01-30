package ldif

import (
	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

func (l *LdifBackend) Extended(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	l.Log.Debug("Extended request received", log.Ctx{"name": r.RequestName(), "value": r.RequestValue()})
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
