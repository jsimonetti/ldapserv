package ldif

import log "gopkg.in/inconshreveable/log15.v2"

type ldif struct {
	dn   string
	attr []attr
}

type attr struct {
	name    string
	content []byte
	atype   uint
}

const (
	ATTR_TYPE_TEXT   uint = 0x1
	ATTR_TYPE_BINARY uint = 0x2
)

type LdifBackend struct {
	ldifs []ldif
	Path  string
	Log   log.Logger
}
