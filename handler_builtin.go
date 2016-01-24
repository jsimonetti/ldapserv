package main

import (
	"crypto/tls"
	"fmt"

	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

func handleSearchDSE(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	r := m.GetSearchRequest()

	logger.Debug("Request", log.Ctx{"basedn": r.BaseObject(), "filter": r.Filter(), "filterString": r.FilterString(), "attributes": r.Attributes(), "timeLimit": r.TimeLimit().Int()})

	e := ldap.NewSearchResultEntry("")
	e.AddAttribute("vendorName", "Jeroen Simonetti")
	e.AddAttribute("vendorVersion", "0.0.1")
	e.AddAttribute("objectClass", "top", "extensibleObject")
	e.AddAttribute("supportedLDAPVersion", "3")
	e.AddAttribute("namingContexts", "o=Pronoc, c=Net")
	e.AddAttribute("supportedExtension", "1.3.6.1.4.1.1466.20037")
	// e.AddAttribute("subschemaSubentry", "cn=schema")
	// e.AddAttribute("namingContexts", "ou=system", "ou=schema", "dc=example,dc=com", "ou=config")
	// e.AddAttribute("supportedFeatures", "1.3.6.1.4.1.4203.1.5.1")
	// e.AddAttribute("supportedControl", "2.16.840.1.113730.3.4.3", "1.3.6.1.4.1.4203.1.10.1", "2.16.840.1.113730.3.4.2", "1.3.6.1.4.1.4203.1.9.1.4", "1.3.6.1.4.1.42.2.27.8.5.1", "1.3.6.1.4.1.4203.1.9.1.1", "1.3.6.1.4.1.4203.1.9.1.3", "1.3.6.1.4.1.4203.1.9.1.2", "1.3.6.1.4.1.18060.0.0.1", "2.16.840.1.113730.3.4.7", "1.2.840.113556.1.4.319")
	// e.AddAttribute("supportedExtension", "1.3.6.1.4.1.1466.20036", "1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.18060.0.1.5", "1.3.6.1.4.1.18060.0.1.3", "1.3.6.1.4.1.1466.20037")
	// e.AddAttribute("supportedSASLMechanisms", "NTLM", "GSSAPI", "GSS-SPNEGO", "CRAM-MD5", "SIMPLE", "DIGEST-MD5")
	// e.AddAttribute("entryUUID", "f290425c-8272-4e62-8a67-92b06f38dbf5")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleSearchMyCompany(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	r := m.GetSearchRequest()
	logger.Debug("handleSearchMyCompany", log.Ctx{"baseDn": r.BaseObject()})

	e := ldap.NewSearchResultEntry(string(r.BaseObject()))
	e.AddAttribute("objectClass", "top", "organizationalUnit")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleStartTLS(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	tlsconfig, _ := getTLSconfig()
	tlsConn := tls.Server(m.Client.GetConn(), tlsconfig)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	res.SetResponseName(ldap.NoticeOfStartTLS)
	w.Write(res)

	if err := tlsConn.Handshake(); err != nil {
		logger.Error("StartTLS Handshake error", log.Ctx{"error": err})
		res.SetDiagnosticMessage(fmt.Sprintf("StartTLS Handshake error : \"%s\"", err.Error()))
		res.SetResultCode(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	m.Client.SetConn(tlsConn)
	logger.Debug("StartTLS OK")
}

func handleDefaultBind(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	res := ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("No backend found")
	w.Write(res)
}

func handleDefaultSearch(w ldap.ResponseWriter, m *ldap.Message, backend ldap.Backend) {
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultUnwillingToPerform)
	w.Write(res)
}
