package ldif

import (
	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

func (l *LdifBackend) Abandon(w ldap.ResponseWriter, m *ldap.Message) {
	var req = m.GetAbandonRequest()
	// retreive the request to abandon, and send a abort signal to it
	if requestToAbandon, ok := m.Client.GetMessageByID(int(req)); ok {
		requestToAbandon.Abandon()
		l.Log.Debug("Abandon signal sent to request processor", log.Ctx{"messageID": int(req)})
	}
}
