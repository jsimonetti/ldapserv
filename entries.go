package main

import (
	"strings"

	"github.com/vjeantet/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
)

func getEntriesAfterFilter(basedn message.LDAPDN, filter message.Filter, attributes message.AttributeSelection) ([]message.SearchResultEntry, int) {

	var entries []message.SearchResultEntry

	for _, ldif := range ldifs {
		if ldif.dn == string(basedn) {
			if m, result := matchesFilter(filter, ldif); m != true {
				if result != ldap.LDAPResultSuccess {
					return make([]message.SearchResultEntry, 0), result
				}
				continue
			}
			entry := formatEntry(&ldif, attributes)
			entries = append(entries, entry)
			continue
		}
		if strings.HasSuffix(ldif.dn, string(basedn)) {
			if m, result := matchesFilter(filter, ldif); m != true {
				if result != ldap.LDAPResultSuccess {
					return make([]message.SearchResultEntry, 0), result
				}
				continue
			}
			entry := formatEntry(&ldif, attributes)
			entries = append(entries, entry)
			continue
		}
	}

	return entries, ldap.LDAPResultSuccess
}

func formatEntry(ldif *ldif, attributes message.AttributeSelection) message.SearchResultEntry {
	e := ldap.NewSearchResultEntry(ldif.dn)

	for _, attr := range ldif.attr {
		if len(attributes) < 1 {
			e.AddAttribute(message.AttributeDescription(attr.name), message.AttributeValue(attr.content))
			continue
		}
		for _, wantattr := range attributes {
			if attr.name == string(wantattr) {
				e.AddAttribute(message.AttributeDescription(attr.name), message.AttributeValue(attr.content))
			}
		}
	}
	return e
}
