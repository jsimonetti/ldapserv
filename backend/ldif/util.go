package ldif

import (
	"bufio"
	"encoding/base64"
	"os"
	"strings"

	"github.com/jsimonetti/ldapserv/ldap"
	"github.com/lor00x/goldap/message"
)

func (l *LdifBackend) readLdif(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()

	dn := ""

	scanner := bufio.NewScanner(file)

	attrs := make([]attr, 0)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 2 {
			continue
		}
		if parts[0] == "dn" {
			if dn != "" {
				l.ldifs = append(l.ldifs, ldif{dn, attrs})
			}
			attrs = make([]attr, 0)
			dn = strings.TrimSpace(parts[1])
		} else {
			if len(parts) == 3 {
				val, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[2]))
				attrs = append(attrs, attr{parts[0], []byte(val), ATTR_TYPE_BINARY})
			} else {
				attrs = append(attrs, attr{parts[0], []byte(strings.TrimSpace(parts[1])), ATTR_TYPE_TEXT})
			}
		}
	}
	l.ldifs = append(l.ldifs, ldif{dn, attrs})

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (l *LdifBackend) formatEntry(ldif *ldif, attributes message.AttributeSelection) message.SearchResultEntry {
	e := ldap.NewSearchResultEntry(ldif.dn)
	var content string
	for _, attr := range ldif.attr {
		if attr.name == "userPassword" {
			continue
		}
		if attr.atype == ATTR_TYPE_TEXT {
			content = string(attr.content)
		} else {
			content = ":" + base64.StdEncoding.EncodeToString(attr.content)
		}
		if len(attributes) < 1 {
			e.AddAttribute(message.AttributeDescription(attr.name), message.AttributeValue(content))
			continue
		}
		for _, wantattr := range attributes {
			if attr.name == string(wantattr) {
				e.AddAttribute(message.AttributeDescription(attr.name), message.AttributeValue(content))
			}
		}
	}
	return e
}
