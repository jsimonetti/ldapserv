package ldif

import (
	"github.com/jsimonetti/ldapserv/ldap"
	"github.com/lor00x/goldap/message"
	log "gopkg.in/inconshreveable/log15.v2"
)

func (l *LdifBackend) Bind(r message.BindRequest) int {
	l.Log.Debug("Bind", log.Ctx{"authchoice": r.AuthenticationChoice(), "user": r.Name()})
	if r.AuthenticationChoice() == "simple" {
		//search for userdn
		for _, ldif := range l.ldifs {
			if ldif.dn == string(r.Name()) {
				//Check password
				for _, attr := range ldif.attr {

					if attr.name == "userPassword" {
						if string(attr.content) == string(r.AuthenticationSimple()) {
							return ldap.LDAPResultSuccess
						}
						l.Log.Debug("userPassword doesn't match", log.Ctx{"pass": r.Authentication(), "userPassword": attr.content})
						break
					}
				}
				l.Log.Debug("no userPassword found!")
				break
			}
		}
		l.Log.Info("Bind failed", log.Ctx{"user": r.Name(), "pass": r.Authentication()})
		return ldap.LDAPResultInvalidCredentials
	} else {
		return ldap.LDAPResultUnwillingToPerform
	}
}
