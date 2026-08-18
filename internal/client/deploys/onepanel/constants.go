package onepanel

import "time"

const (
	onePanelRequestTimeout          = 30 * time.Second
	onePanelDiscoveryTimeout        = 15 * time.Second
	onePanelMaxResponseBodySize     = 4 * 1024 * 1024
	onePanelWebsitePageSize         = 100
	onePanelWebsiteMaxPages         = 1000
	onePanelWebsiteDomainWorkers    = 4
	onePanelSSLSearchPath           = "/api/v2/websites/ssl/search"
	onePanelSSLUploadPath           = "/api/v2/websites/ssl/upload"
	onePanelWebsiteSearchPath       = "/api/v2/websites/search"
	onePanelWebsiteDomainsPath      = "/api/v2/websites/domains/%d"
	onePanelWebsiteHTTPSPath        = "/api/v2/websites/%d/https"
	onePanelWebsiteTargetRefPrefix  = "onepanel-site-"
	onePanelWebsiteDescription      = "由 anSSL 自动部署"
	onePanelDefaultHTTPConfig       = "HTTPToHTTPS"
	onePanelWebsiteProtocolHTTP     = "HTTP"
	onePanelWebsiteProtocolHTTPS    = "HTTPS"
	onePanelWebsiteStatusRunning    = "Running"
	onePanelWebsiteStatusStopped    = "Stopped"
	onePanelWebsiteResourceProvider = "ansslCli"
)
