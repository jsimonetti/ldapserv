package main

import "github.com/jsimonetti/ldapserv/ldap"

func newRouter(fallback ldap.Backend) *ldap.RouteMux {

	starttls := &StartTLSBackend{}
	//Create routes bindings
	routes := ldap.NewRouteMux()

	// buildins
	routes.Search(fallback).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - ROOT DSE")
	routes.Search(fallback).
		BaseDn("o=Pronoc, c=Net").
		Scope(ldap.SearchRequestScopeBaseObject).
		Label("Search - Company Root")
	routes.Extended(starttls).
		RequestName(ldap.NoticeOfStartTLS).Label("StartTLS")

	//default routes
	routes.NotFound(fallback)
	routes.Abandon(fallback)
	routes.Compare(fallback)
	routes.Delete(fallback)
	routes.Modify(fallback)
	routes.Extended(fallback).
		RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")
	routes.Extended(fallback).Label("Ext - Generic")

	routes.Add(fallback).Label("Default Add")
	routes.Bind(fallback).Label("Default Bind")
	routes.Search(fallback).Label("Default Search")

	return routes
}
