package main

import (
	ldap "github.com/jsimonetti/ldapserver"
	log "gopkg.in/inconshreveable/log15.v2"
)

func handleModify(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	r := m.GetModifyRequest()
	logger.Debug("Modify entry", log.Ctx{"entry": r.Object()})

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

		logger.Debug("attribute change", log.Ctx{"operation": operationString, "type": modification.Type_()})
		for _, attributeValue := range modification.Vals() {
			logger.Debug("value", log.Ctx{"value": attributeValue})
		}

	}

	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
