package debug

import "github.com/jsimonetti/ldapserv/ldap"

func (d *DebugBackend) NotFound(w ldap.ResponseWriter, m *ldap.Message) {
	dump(m)
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
