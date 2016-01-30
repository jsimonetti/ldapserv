package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/jsimonetti/ldapserv/backend/debug"
	"github.com/jsimonetti/ldapserv/backend/ldif"
	"github.com/jsimonetti/ldapserv/ldap"
	log "gopkg.in/inconshreveable/log15.v2"
)

var logger log.Logger

func main() {

	logger = log.New()

	ldifstore := &ldif.LdifBackend{
		Path: "./ldif",
		Log:  logger.New(log.Ctx{"backend": "ldif"}),
	}

	if err := ldifstore.Run(); err != nil {
		logger.Error("error loading backend", log.Ctx{"error": err})
		os.Exit(1)
	}

	//Create a new LDAP Server
	server := ldap.NewServer()

	fallback := &debug.DebugBackend{
		Log: logger.New(log.Ctx{"backend": "debug"}),
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
