package debug

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

type DebugBackend struct {
	Log log.Logger
}

func (d *DebugBackend) Start() error {
	return nil
}

func (d *DebugBackend) Add(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAddRequest()
	spew.Dump(r)
	res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
	w.Write(res)
}

func (d *DebugBackend) Bind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	spew.Dump(r)
	res := ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform)
	w.Write(res)
}

func (d *DebugBackend) Delete(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetDeleteRequest()
	spew.Dump(r)
	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) Extended(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	spew.Dump(r)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) Modify(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyRequest()
	spew.Dump(r)
	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) Search(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	spew.Dump(r)
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) Abandon(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAbandonRequest()
	spew.Dump(m)
	// retreive the request to abandon, and send a abort signal to it
	if requestToAbandon, ok := m.Client.GetMessageByID(int(r)); ok {
		requestToAbandon.Abandon()
	}
}

func (d *DebugBackend) Compare(w ldap.ResponseWriter, m *ldap.Message) {
	//r := m.GetCompareRequest()
	fmt.Println("COMPARE %#v\n", m)
	spew.Dump(m)
	res := ldap.NewCompareResponse(ldap.LDAPResultCompareTrue)
	w.Write(res)
}

func (d *DebugBackend) NotFound(w ldap.ResponseWriter, m *ldap.Message) {
	fmt.Println("NotFound %#v\n", m)
	spew.Dump(m)
	switch m.ProtocolOpType() {
	case ldap.ApplicationBindRequest:
		res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
		res.SetDiagnosticMessage("Default binding behavior set to return Success")

		w.Write(res)

	default:
		res := ldap.NewResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}
}
