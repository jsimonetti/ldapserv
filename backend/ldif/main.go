package ldif

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/jsimonetti/ldapserv/ldap"
	"github.com/lor00x/goldap/message"
	log "gopkg.in/inconshreveable/log15.v2"
)

type ldif struct {
	dn   string
	attr []attr
}

type attr struct {
	name    string
	content string
}

type LdifBackend struct {
	ldifs []ldif
	Path  string
	Log   log.Logger
}

func (l *LdifBackend) Run() error {
	files, _ := ioutil.ReadDir(l.Path)
	for _, f := range files {
		if err := l.readLdif(fmt.Sprintf("%s/%s", l.Path, f.Name())); err != nil {
			return err
		}
	}
	return nil
}

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
			attrs = append(attrs, attr{parts[0], strings.TrimSpace(parts[1])})
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

	for _, attr := range ldif.attr {
		if attr.name == "userPassword" {
			continue
		}
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
