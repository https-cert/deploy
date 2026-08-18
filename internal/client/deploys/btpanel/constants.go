package btpanel

import "time"

const (
	btPanelRequestTimeout       = 30 * time.Second
	btPanelDiscoveryTimeout     = 20 * time.Second
	btPanelMaxResponseBodySize  = 4 * 1024 * 1024
	btPanelWebsitePageSize      = 100
	btPanelWebsiteMaxPages      = 100
	btPanelWebsiteDomainWorkers = 4
	btPanelWebsiteTargetPrefix  = "btpanel-site-"
	btPanelDataPath             = "/data"
	btPanelSitePath             = "/site"
	btPanelSSLPath              = "/ssl"
	btPanelCertificateSavePath  = "/ssl/cert/save_cert"
	btPanelStatusRunning        = "Running"
	btPanelStatusStopped        = "Stopped"
	btPanelProtocolHTTP         = "HTTP"
	btPanelProtocolHTTPS        = "HTTPS"
)
