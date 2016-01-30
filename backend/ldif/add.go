package ldif

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

func (l *LdifBackend) Add(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAddRequest()
	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		l.Log.Debug("Leaving Add... stop signal")
		return
	default:
	}

	l.Log.Debug("Adding entry", log.Ctx{"entry": r.Entry()})

	entry := ldif{dn: string(r.Entry())}

	for _, attribute := range r.Attributes() {
		for _, attributeValue := range attribute.Vals() {
			if isValueBinary([]byte(attributeValue)) {
				value := base64.StdEncoding.EncodeToString([]byte(attributeValue))
				entry.attr = append(entry.attr, attr{name: string(attribute.Type_()), content: []byte(value), atype: ATTR_TYPE_BINARY})
				l.Log.Debug("attribute", log.Ctx{"type": attribute.Type_(), "value": string(value), "atype": "binary"})
			} else {
				entry.attr = append(entry.attr, attr{name: string(attribute.Type_()), content: []byte(attributeValue), atype: ATTR_TYPE_TEXT})
				l.Log.Debug("attribute", log.Ctx{"type": attribute.Type_(), "value": string(attributeValue), "atype": "string"})
			}
		}
	}
	if ok, err := l.saveEntry(entry); ok {
		l.ldifs = append(l.ldifs, entry)
		res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
		w.Write(res)
		return
	} else {
		l.Log.Debug("Add entry error", log.Ctx{"error": err})
	}
	res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
	w.Write(res)
}

func (l *LdifBackend) saveEntry(entry ldif) (bool, error) {

	fname := l.Path + "/" + entry.dn + ".ldif"
	if _, err := os.Stat(fname); err == nil {
		return false, os.ErrExist
	}

	f, _ := os.Create(fname)
	f.Write([]byte(fmt.Sprintf("dn: %s\n", entry.dn)))

	for _, attr := range entry.attr {
		if attr.atype == ATTR_TYPE_TEXT {
			f.Write([]byte(fmt.Sprintf("%s: %s\n", attr.name, string(attr.content))))
		} else {
			f.Write([]byte(fmt.Sprintf("%s:: %s\n", attr.name, string(attr.content))))
		}
	}
	return true, nil
}

func isValueBinary(value []byte) bool {
	for _, r := range value {
		if strconv.IsPrint(rune(r)) == false {
			return true
		}
	}
	return false
}
