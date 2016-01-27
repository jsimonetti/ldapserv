package ldap

import "github.com/lor00x/goldap/message"

// Backend is implemented by an LDAP database to provide the backing store
type Backend interface {
	Search(r message.SearchRequest) ([]message.SearchResultEntry, int)
	Bind(r message.BindRequest) int
	Add(r message.AddRequest) int
}
