package main

import (
	ldap "github.com/jsimonetti/ldapserver"
	log "gopkg.in/inconshreveable/log15.v2"
)

// The resultCode is set to compareTrue, compareFalse, or an appropriate
// error.  compareTrue indicates that the assertion value in the ava
// Comparerequest field matches a value of the attribute or subtype according to the
// attribute's EQUALITY matching rule.  compareFalse indicates that the
// assertion value in the ava field and the values of the attribute or
// subtype did not match.  Other result codes indicate either that the
// result of the comparison was Undefined, or that
// some error occurred.
func handleCompare(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetCompareRequest()
	logger.Debug("Comparing entry", log.Ctx{"entry": r.Entry(), "name": r.Ava().AttributeDesc(), "value": r.Ava().AssertionValue()})
	//attributes values

	res := ldap.NewCompareResponse(ldap.LDAPResultCompareTrue)

	w.Write(res)
}

func handleModify(w ldap.ResponseWriter, m *ldap.Message) {
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

func handleDelete(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetDeleteRequest()
	logger.Debug("Deleting entry", log.Ctx{"entry": r})
	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleExtended(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	logger.Debug("Extended request received", log.Ctx{"name": r.RequestName(), "value": r.RequestValue()})
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
