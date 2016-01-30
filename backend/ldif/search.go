package ldif

import (
	"strings"

	"github.com/jsimonetti/ldapserv/ldap"
	"github.com/lor00x/goldap/message"
	log "gopkg.in/inconshreveable/log15.v2"
)

func (l *LdifBackend) Search(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		l.Log.Debug("Leaving Search... stop signal")
		return
	default:
	}

	l.Log.Debug("Search", log.Ctx{"basedn": r.BaseObject(), "filter": r.Filter(), "filterString": r.FilterString(), "attributes": r.Attributes(), "timeLimit": r.TimeLimit().Int()})

	var entries []message.SearchResultEntry

	for _, ldif := range l.ldifs {
		if strings.ToLower(ldif.dn) == strings.ToLower(string(r.BaseObject())) {
			if m, result := matchesFilter(r.Filter(), ldif); m != true {
				if result != ldap.LDAPResultSuccess {
					res := ldap.NewSearchResultDoneResponse(result)
					w.Write(res)
					//return make([]message.SearchResultEntry, 0), result
					return
				}
				continue
			}
			entry := l.formatEntry(&ldif, r.Attributes())
			entries = append(entries, entry)
			continue
		}
		if strings.HasSuffix(strings.ToLower(ldif.dn), strings.ToLower(string(r.BaseObject()))) {
			if m, result := matchesFilter(r.Filter(), ldif); m != true {
				if result != ldap.LDAPResultSuccess {
					res := ldap.NewSearchResultDoneResponse(result)
					w.Write(res)
					//return make([]message.SearchResultEntry, 0), result
					return
				}
				continue
			}
			entry := l.formatEntry(&ldif, r.Attributes())
			entries = append(entries, entry)
			continue
		}
	}

	for i := 0; i < len(entries); i++ {
		w.Write(entries[i])
	}

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
