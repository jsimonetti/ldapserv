package main

import (
	"crypto/tls"
	"fmt"

	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

func newRouter(fallback ldap.Backend, logger log.Logger) *ldap.RouteMux {

	defaults := &DefaultsBackend{
		Log: logger.New(log.Ctx{"type": "backend", "backend": "defaults"}),
	}

	//Create routes bindings
	routes := ldap.NewRouteMux(logger)

	// buildins
	routes.Search(defaults).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - ROOT DSE")
	routes.Search(defaults).
		BaseDn("o=Pronoc, c=Net").
		Scope(ldap.SearchRequestScopeBaseObject).
		Label("Search - Company Root")
	routes.Extended(defaults).
		RequestName(ldap.NoticeOfStartTLS).Label("StartTLS")

	//default routes
	routes.NotFound(fallback)
	routes.Abandon(fallback)
	routes.Compare(fallback)
	routes.Delete(fallback)
	routes.Modify(fallback)
	routes.Extended(fallback).
		RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")
	routes.Extended(fallback).Label("Ext - Generic")

	routes.Add(fallback).Label("Default Add")
	routes.Bind(fallback).Label("Default Bind")
	routes.Search(fallback).Label("Default Search")

	return routes
}

type DefaultsBackend struct {
	Log log.Logger
}

func (d *DefaultsBackend) Extended(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	if r.RequestName() == ldap.NoticeOfStartTLS {
		d.startTLS(w, m)
	}
}

func (d *DefaultsBackend) Search(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	if r.BaseObject() == "" && r.Scope() == ldap.SearchRequestScopeBaseObject && r.FilterString() == "(objectclass=*)" {
		d.searchDSE(w, m)
		return
	}
	if r.BaseObject() == "o=Pronoc, c=Net" && r.Scope() == ldap.SearchRequestScopeBaseObject {
		d.searchMyCompany(w, m)
	}
}
func (d *DefaultsBackend) searchDSE(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	d.Log.Debug("SearchDSE", log.Ctx{"basedn": r.BaseObject(), "filter": r.Filter(), "filterString": r.FilterString(), "attributes": r.Attributes(), "timeLimit": r.TimeLimit().Int()})

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

func (d *DefaultsBackend) searchMyCompany(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	d.Log.Debug("SearchMyCompany", log.Ctx{"basedn": r.BaseObject(), "filter": r.Filter(), "filterString": r.FilterString(), "attributes": r.Attributes(), "timeLimit": r.TimeLimit().Int()})

	e := ldap.NewSearchResultEntry(string(r.BaseObject()))
	e.AddAttribute("objectClass", "top", "organizationalUnit")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DefaultsBackend) startTLS(w ldap.ResponseWriter, m *ldap.Message) {
	tlsconfig, _ := d.getTLSconfig()
	tlsConn := tls.Server(m.Client.GetConn(), tlsconfig)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	res.SetResponseName(ldap.NoticeOfStartTLS)
	w.Write(res)

	if err := tlsConn.Handshake(); err != nil {
		d.Log.Error("StartTLS Handshake error", log.Ctx{"error": err})
		res.SetDiagnosticMessage(fmt.Sprintf("StartTLS Handshake error : \"%s\"", err.Error()))
		res.SetResultCode(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	m.Client.SetConn(tlsConn)
	d.Log.Debug("StartTLS OK")
}

// getTLSconfig returns a tls configuration used
// to build a TLSlistener for TLS or StartTLS
func (d *DefaultsBackend) getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionSSL30,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "127.0.0.1",
	}, nil
}

// localhostCert is a PEM-encoded TLS cert with SAN DNS names
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBOTCB5qADAgECAgEAMAsGCSqGSIb3DQEBBTAAMB4XDTcwMDEwMTAwMDAwMFoX
DTQ5MTIzMTIzNTk1OVowADBaMAsGCSqGSIb3DQEBAQNLADBIAkEAsuA5mAFMj6Q7
qoBzcvKzIq4kzuT5epSp2AkcQfyBHm7K13Ws7u+0b5Vb9gqTf5cAiIKcrtrXVqkL
8i1UQF6AzwIDAQABo08wTTAOBgNVHQ8BAf8EBAMCACQwDQYDVR0OBAYEBAECAwQw
DwYDVR0jBAgwBoAEAQIDBDAbBgNVHREEFDASggkxMjcuMC4wLjGCBVs6OjFdMAsG
CSqGSIb3DQEBBQNBAJH30zjLWRztrWpOCgJL8RQWLaKzhK79pVhAx6q/3NrF16C7
+l1BRZstTwIGdoGId8BRpErK1TXkniFb95ZMynM=
-----END CERTIFICATE-----
`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPQIBAAJBALLgOZgBTI+kO6qAc3LysyKuJM7k+XqUqdgJHEH8gR5uytd1rO7v
tG+VW/YKk3+XAIiCnK7a11apC/ItVEBegM8CAwEAAQJBAI5sxq7naeR9ahyqRkJi
SIv2iMxLuPEHaezf5CYOPWjSjBPyVhyRevkhtqEjF/WkgL7C2nWpYHsUcBDBQVF0
3KECIQDtEGB2ulnkZAahl3WuJziXGLB+p8Wgx7wzSM6bHu1c6QIhAMEp++CaS+SJ
/TrU0zwY/fW4SvQeb49BPZUF3oqR8Xz3AiEA1rAJHBzBgdOQKdE3ksMUPcnvNJSN
poCcELmz2clVXtkCIQCLytuLV38XHToTipR4yMl6O+6arzAjZ56uq7m7ZRV0TwIh
AM65XAOw8Dsg9Kq78aYXiOEDc5DL0sbFUu/SlmRcCg93
-----END RSA PRIVATE KEY-----
`)

func (d *DefaultsBackend) Add(w ldap.ResponseWriter, m *ldap.Message)            {}
func (d *DefaultsBackend) Bind(w ldap.ResponseWriter, m *ldap.Message)           {}
func (d *DefaultsBackend) Delete(w ldap.ResponseWriter, m *ldap.Message)         {}
func (d *DefaultsBackend) Modify(w ldap.ResponseWriter, m *ldap.Message)         {}
func (d *DefaultsBackend) ModifyDN(w ldap.ResponseWriter, m *ldap.Message)       {}
func (d *DefaultsBackend) PasswordModify(w ldap.ResponseWriter, m *ldap.Message) {}
func (d *DefaultsBackend) Whoami(w ldap.ResponseWriter, m *ldap.Message)         {}
func (d *DefaultsBackend) Abandon(w ldap.ResponseWriter, m *ldap.Message)        {}
func (d *DefaultsBackend) Compare(w ldap.ResponseWriter, m *ldap.Message)        {}
func (d *DefaultsBackend) NotFound(w ldap.ResponseWriter, m *ldap.Message)       {}
