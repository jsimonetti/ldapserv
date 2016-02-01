package debug

import log "gopkg.in/inconshreveable/log15.v2"

type DebugBackend struct {
	Log log.Logger
}
