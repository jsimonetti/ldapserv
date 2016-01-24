package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	ldap "github.com/jsimonetti/ldapserver"
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
	path  string
	log   log.Logger
}

func (l *LdifBackend) Run() error {
	l.path = "./ldif"
	files, _ := ioutil.ReadDir(l.path)
	for _, f := range files {
		if err := l.readLdif(fmt.Sprintf("%s/%s", l.path, f.Name())); err != nil {
			return err
		}
	}
	return nil
}

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

func (l *LdifBackend) Search(r message.SearchRequest) ([]message.SearchResultEntry, int) {
	l.log.Debug("Search", log.Ctx{"basedn": r.BaseObject(), "filter": r.Filter(), "filterString": r.FilterString(), "attributes": r.Attributes(), "timeLimit": r.TimeLimit().Int()})

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
