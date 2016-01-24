package ldif

import (
	ldap "github.com/jsimonetti/ldapserver"
	"github.com/lor00x/goldap/message"
	log "gopkg.in/inconshreveable/log15.v2"
)

func (l *LdifBackend) Bind(r message.BindRequest) int {
	l.log.Debug("Bind", log.Ctx{"authchoice": r.AuthenticationChoice(), "user": r.Name()})
	if r.AuthenticationChoice() == "simple" {
		//search for userdn
		for _, ldif := range l.ldifs {
			if ldif.dn == string(r.Name()) {
				//Check password
				for _, attr := range ldif.attr {

					if attr.name == "userPassword" {
						if attr.content == string(r.AuthenticationSimple()) {
							return ldap.LDAPResultSuccess
						}
						l.log.Debug("userPassword doesn't match", log.Ctx{"pass": r.Authentication(), "userPassword": attr.content})
						break
					}
				}
				l.log.Debug("no userPassword found!")
				break
			}
		}
		l.log.Info("Bind failed", log.Ctx{"user": r.Name(), "pass": r.Authentication()})
		return ldap.LDAPResultInvalidCredentials
	} else {
		return ldap.LDAPResultUnwillingToPerform
	}
}
