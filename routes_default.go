package main

import "github.com/jsimonetti/ldapserv/ldap"

func newRouter() *ldap.RouteMux {
	//Create routes bindings
	routes := ldap.NewRouteMux()

	// buildins
	routes.Search(handleSearchDSE).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - ROOT DSE")
	routes.Search(handleSearchMyCompany).
		BaseDn("o=Pronoc, c=Net").
		Scope(ldap.SearchRequestScopeBaseObject).
		Label("Search - Company Root")
	routes.Extended(handleStartTLS).
		RequestName(ldap.NoticeOfStartTLS).Label("StartTLS")

	//default routes
	routes.NotFound(handleNotFound)
	routes.Abandon(handleAbandon)
	routes.Compare(handleCompare)
	routes.Delete(handleDelete)
	routes.Modify(handleModify)
	routes.Extended(handleWhoAmI).
		RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")
	routes.Extended(handleExtended).Label("Ext - Generic")

	routes.Add(handleDefaultAdd).Label("Default Add")
	routes.Bind(handleDefaultBind).Label("Default Bind")
	routes.Search(handleDefaultSearch).Label("Default Search")

	return routes
}
