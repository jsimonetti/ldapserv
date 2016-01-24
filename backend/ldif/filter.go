package ldif

import (
	"strings"

	ldap "github.com/jsimonetti/ldapserver"
	"github.com/lor00x/goldap/message"
)

func matchesFilter(packet message.Filter, e ldif) (bool, int) {

	switch f := packet.(type) {
	default:
		return false, ldap.LDAPResultOperationsError
	case message.FilterEqualityMatch:
		attribute := string(f.AttributeDesc())
		value := string(f.AssertionValue())
		for _, a := range e.attr {
			if strings.ToLower(a.name) == strings.ToLower(attribute) {
				if strings.ToLower(a.content) == strings.ToLower(value) {
					return true, ldap.LDAPResultSuccess
				}

			}
		}
	case message.FilterPresent:
		for _, a := range e.attr {
			if strings.ToLower(a.name) == strings.ToLower(string(f)) {
				return true, ldap.LDAPResultSuccess
			}
		}
	case message.FilterAnd:
		for _, child := range f {
			ok, exitCode := matchesFilter(child, e)
			if exitCode != ldap.LDAPResultSuccess {
				return false, exitCode
			}
			if !ok {
				return false, ldap.LDAPResultSuccess
			}
		}
		return true, ldap.LDAPResultSuccess
	case message.FilterOr:
		anyOk := false
		for _, child := range f {
			ok, exitCode := matchesFilter(child, e)
			if exitCode != ldap.LDAPResultSuccess {
				return false, exitCode
			} else if ok {
				anyOk = true
			}
		}
		if anyOk {
			return true, ldap.LDAPResultSuccess
		}
	case message.FilterNot:
		ok, exitCode := matchesFilter(f, e)
		if exitCode != ldap.LDAPResultSuccess {
			return false, exitCode
		} else if !ok {
			return true, ldap.LDAPResultSuccess
		}
	case message.FilterSubstrings:
		attribute := string(f.Type_())
		for _, a := range e.attr {
			if strings.ToLower(a.name) == strings.ToLower(attribute) {
				for _, fs := range f.Substrings() {
					switch fsv := fs.(type) {
					case message.SubstringInitial:
						if strings.HasPrefix(a.content, string(fsv)) {
							return true, ldap.LDAPResultSuccess
						}
					case message.SubstringAny:
						if strings.Contains(a.content, string(fsv)) {
							return true, ldap.LDAPResultSuccess
						}
					case message.SubstringFinal:
						if strings.HasSuffix(a.content, string(fsv)) {
							return true, ldap.LDAPResultSuccess
						}
					}
				}
			}
		}
	case message.FilterGreaterOrEqual: // TODO
		return false, ldap.LDAPResultOperationsError
	case message.FilterLessOrEqual: // TODO
		return false, ldap.LDAPResultOperationsError
	case message.FilterApproxMatch: // TODO
		return false, ldap.LDAPResultOperationsError
	case message.FilterExtensibleMatch: // TODO
		return false, ldap.LDAPResultOperationsError
	}

	return false, ldap.LDAPResultSuccess
}
