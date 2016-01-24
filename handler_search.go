package main

import (
	ldap "github.com/jsimonetti/ldapserver"
	log "gopkg.in/inconshreveable/log15.v2"
)

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	logger.Debug("handleSearch", log.Ctx{"basedn": r.BaseObject(), "filter": r.Filter(), "filterString": r.FilterString(), "attributes": r.Attributes(), "timeLimit": r.TimeLimit().Int()})
	logger.Debug("handleSearch", log.Ctx{"baseDn": r.BaseObject()})

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		logger.Debug("Leaving handleSearch...")
		return
	default:
	}

	entries, result := getEntriesAfterFilter(r.BaseObject(), r.Filter(), r.Attributes())

	for i := 0; i < len(entries); i++ {
		w.Write(entries[i])
	}

	res := ldap.NewSearchResultDoneResponse(result)
	w.Write(res)
}
