package ldap

// Backend is implemented by an LDAP database to provide the backing store
type Backend interface {
	Start() error
	NotFound(ResponseWriter, *Message)
	Bind(ResponseWriter, *Message)
	Search(ResponseWriter, *Message)
	Add(ResponseWriter, *Message)
	Delete(ResponseWriter, *Message)
	Modify(ResponseWriter, *Message)
	ModifyDN(ResponseWriter, *Message)
	Extended(ResponseWriter, *Message)
	Compare(ResponseWriter, *Message)
	Abandon(ResponseWriter, *Message)
}
