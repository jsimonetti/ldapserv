package main

import (
	"flag"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jsimonetti/ldapserv/backend/debug"
	"github.com/jsimonetti/ldapserv/backend/ldif"
	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

// Global variables
var debugflag bool
var verboseflag bool
var quietflag bool
var helpflag bool

var logger log.Logger

func init() {
	rand.Seed(time.Now().UTC().UnixNano())

	flag.BoolVar(&debugflag, "debug", false, "show debug logging")
	flag.BoolVar(&verboseflag, "verbose", false, "show verbose logging")
	flag.BoolVar(&quietflag, "quiet", false, "suppress logging")
	flag.BoolVar(&helpflag, "help", false, "show usage")
}

func main() {
	flag.Parse()
	if helpflag {
		flag.Usage()
		return
	}

	logger = log.New()

	handler := log.StdoutHandler
	if quietflag {
		logger.SetHandler(log.DiscardHandler())
	} else if verboseflag {
		logger.SetHandler(log.LvlFilterHandler(log.LvlInfo, handler))
	} else if debugflag {
		logger.SetHandler(log.LvlFilterHandler(log.LvlDebug, handler))
	} else {
		logger.SetHandler(log.LvlFilterHandler(log.LvlError, handler))
	}

	ldifstore := &ldif.LdifBackend{
		Path: "./ldif",
		Log:  logger.New(log.Ctx{"type": "backend", "backend": "ldif"}),
	}

	if err := ldifstore.Run(); err != nil {
		logger.Error("error loading backend", log.Ctx{"error": err})
		os.Exit(1)
	}

	//Create a new LDAP Server
	server := ldap.NewServer(logger)

	fallback := &debug.DebugBackend{
		Log: logger.New(log.Ctx{"type": "backend", "backend": "debug"}),
	}

	//Create routes bindings
	routes := newRouter(fallback, logger)

	// backend specific routes
	routes.Bind(ldifstore).BaseDn("dc=enterprise,dc=org").Label("Bind LDIF")
	routes.Search(ldifstore).BaseDn("dc=enterprise,dc=org").Label("Search LDIF")
	routes.Add(ldifstore).BaseDn("dc=enterprise,dc=org").Label("Add LDIF")

	//Attach routes to server
	server.Handle(routes)

	// listen on 3389 and serve
	go server.ListenAndServe(":3389")

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}
