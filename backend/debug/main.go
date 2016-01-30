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

func (DebugBackend) Dump(obj interface{}) {
	spew.Dump(obj)
}

func (d *DebugBackend) Add(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAddRequest()
	fmt.Printf("ADD %#v\n", r)
	d.Dump(m)
	res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
	w.Write(res)
}

func (d *DebugBackend) Bind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	fmt.Printf("BIND %#v\n", r)
	d.Dump(m)
	res := ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform)
	w.Write(res)
}

func (d *DebugBackend) Delete(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetDeleteRequest()
	fmt.Printf("DELETE %#v\n", r)
	d.Dump(m)
	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) ExtendedRequest(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	fmt.Printf("EXTENDED %#v\n", r)
	d.Dump(m)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) Modify(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyRequest()
	fmt.Printf("MODIFY dn=%s\n", r.Object())
	d.Dump(m)
	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) ModifyDN(w ldap.ResponseWriter, m *ldap.Message) {
	fmt.Printf("MODIFYDN %#v\n", m)
	d.Dump(m)
	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) PasswordModify(w ldap.ResponseWriter, m *ldap.Message) {
	fmt.Printf("PASSWORD MODIFY %#v\n", m)
	d.Dump(m)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) Search(w ldap.ResponseWriter, m *ldap.Message) {
	fmt.Printf("SEARCH %#v\n", m)
	d.Dump(m)
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) Whoami(w ldap.ResponseWriter, m *ldap.Message) {
	fmt.Println("WHOAMI")
	d.Dump(m)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) Abandon(w ldap.ResponseWriter, m *ldap.Message) {
	var req = m.GetAbandonRequest()
	fmt.Println("ABANDON %#v\n", m)
	d.Dump(m)
	// retreive the request to abandon, and send a abort signal to it
	if requestToAbandon, ok := m.Client.GetMessageByID(int(req)); ok {
		requestToAbandon.Abandon()
	}
}

func (d *DebugBackend) Compare(w ldap.ResponseWriter, m *ldap.Message) {
	//r := m.GetCompareRequest()
	fmt.Println("COMPARE %#v\n", m)
	d.Dump(m)
	res := ldap.NewCompareResponse(ldap.LDAPResultCompareTrue)
	w.Write(res)
}

func (d *DebugBackend) Extended(w ldap.ResponseWriter, m *ldap.Message) {
	//r := m.GetExtendedRequest()
	fmt.Println("EXTENDED %#v\n", m)
	d.Dump(m)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (d *DebugBackend) NotFound(w ldap.ResponseWriter, m *ldap.Message) {
	fmt.Println("NotFound %#v\n", m)
	d.Dump(m)
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
