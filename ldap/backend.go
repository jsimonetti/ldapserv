package ldap

// Backend is implemented by an LDAP database to provide the backing store
type Backend interface {
	NotFound(ResponseWriter, *Message)
	Bind(ResponseWriter, *Message)
	Search(ResponseWriter, *Message)
	Add(ResponseWriter, *Message)
	Delete(ResponseWriter, *Message)
	Modify(ResponseWriter, *Message)
	Extended(ResponseWriter, *Message)
	Compare(ResponseWriter, *Message)
	Abandon(ResponseWriter, *Message)
}
