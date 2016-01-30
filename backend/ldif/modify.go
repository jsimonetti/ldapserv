package ldif

import (
	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

func (l *LdifBackend) Modify(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyRequest()
	l.Log.Debug("Modify entry", log.Ctx{"entry": r.Object()})

	for _, change := range r.Changes() {
		modification := change.Modification()
		var operationString string
		switch change.Operation() {
		case ldap.ModifyRequestChangeOperationAdd:
			operationString = "Add"
		case ldap.ModifyRequestChangeOperationDelete:
			operationString = "Delete"
		case ldap.ModifyRequestChangeOperationReplace:
			operationString = "Replace"
		}

		l.Log.Debug("attribute change", log.Ctx{"operation": operationString, "type": modification.Type_()})
		for _, attributeValue := range modification.Vals() {
			l.Log.Debug("value", log.Ctx{"value": attributeValue})
		}

	}

	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
