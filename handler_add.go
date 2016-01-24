package main

import (
	ldap "github.com/jsimonetti/ldapserver"
	log "gopkg.in/inconshreveable/log15.v2"
)

/*
DBUG[01-24|22:05:14] Adding entry   entry="CN=231fb90b-c92a-40c9-9379-bacfc313a3e3,CN=Operations,CN=DomainUpdates,CN=System,DC=corp,DC=lan"
DBUG[01-24|22:05:14] attribute      value=top type=objectClass
DBUG[01-24|22:05:14] attribute      type=objectClass value=container
DBUG[01-24|22:05:14] attribute      type=cn value=231fb90b-c92a-40c9-9379-bacfc313a3e3
DBUG[01-24|22:05:14] attribute      type=distinguishedName value="CN=231fb90b-c92a-40c9-9379-bacfc313a3e3,CN=Operations,CN=DomainUpdates,CN=System,DC=corp,DC=lan"
DBUG[01-24|22:05:14] attribute      type=instanceType value=4
DBUG[01-24|22:05:14] attribute      type=whenCreated value=20160107105836.0Z
DBUG[01-24|22:05:14] attribute      type=whenChanged value=20160107105836.0Z
DBUG[01-24|22:05:14] attribute      type=uSNCreated value=5803
DBUG[01-24|22:05:14] attribute      type=uSNChanged value=5803
DBUG[01-24|22:05:14] attribute      type=showInAdvancedViewOnly value=TRUE
DBUG[01-24|22:05:14] attribute      type=name value=231fb90b-c92a-40c9-9379-bacfc313a3e3
DBUG[01-24|22:05:14] attribute      type=objectGUID value="�\r�}g��A�1����c"
DBUG[01-24|22:05:14] attribute      type=objectCategory value="CN=Container,CN=Schema,CN=Configuration,DC=corp,DC=lan"
DBUG[01-24|22:05:14] attribute      type=dSCorePropagationData value=20160107105917.0Z
DBUG[01-24|22:05:14] attribute      type=dSCorePropagationData value=16010101000005.0Z

*/

func handleAdd(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAddRequest()
	logger.Debug("Adding entry", log.Ctx{"entry": r.Entry()})
	//attributes values
	for _, attribute := range r.Attributes() {
		for _, attributeValue := range attribute.Vals() {
			logger.Debug("attribute", log.Ctx{"type": attribute.Type_(), "value": string(attributeValue)})
		}
	}
	res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
