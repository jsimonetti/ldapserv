package ldif

import (
	"strings"

	ldap "github.com/jsimonetti/ldapserver"
	"github.com/lor00x/goldap/message"
	log "gopkg.in/inconshreveable/log15.v2"
)

func (l *LdifBackend) Search(r message.SearchRequest) ([]message.SearchResultEntry, int) {
	l.Log.Debug("Search", log.Ctx{"basedn": r.BaseObject(), "filter": r.Filter(), "filterString": r.FilterString(), "attributes": r.Attributes(), "timeLimit": r.TimeLimit().Int()})

	var entries []message.SearchResultEntry

	for _, ldif := range l.ldifs {
		if ldif.dn == string(r.BaseObject()) {
			if m, result := matchesFilter(r.Filter(), ldif); m != true {
				if result != ldap.LDAPResultSuccess {
					return make([]message.SearchResultEntry, 0), result
				}
				continue
			}
			entry := l.formatEntry(&ldif, r.Attributes())
			entries = append(entries, entry)
			continue
		}
		if strings.HasSuffix(ldif.dn, string(r.BaseObject())) {
			if m, result := matchesFilter(r.Filter(), ldif); m != true {
				if result != ldap.LDAPResultSuccess {
					return make([]message.SearchResultEntry, 0), result
				}
				continue
			}
			entry := l.formatEntry(&ldif, r.Attributes())
			entries = append(entries, entry)
			continue
		}
	}

	return entries, ldap.LDAPResultSuccess
}
