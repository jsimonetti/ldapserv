package main

import (
	ldap "github.com/jsimonetti/ldapserver"
	log "gopkg.in/inconshreveable/log15.v2"
)

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
	return

	if r.AuthenticationChoice() == "simple" {
		//search for userdn
		for _, ldif := range ldifs {
			if ldif.dn == string(r.Name()) {
				//Check password
				for _, attr := range ldif.attr {

					if attr.name == "userPassword" {
						if attr.content == string(r.AuthenticationSimple()) {
							w.Write(res)
							return
						}
						logger.Debug("userPassword doesn't match", log.Ctx{"pass": r.Authentication(), "userPassword": attr.content})
						break
					}
				}
				logger.Debug("no userPassword found!")
				break
			}
		}
		logger.Info("Bind failed", log.Ctx{"user": r.Name(), "pass": r.Authentication()})
		res.SetResultCode(ldap.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")
	} else {
		res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
	}

	w.Write(res)
}
