package btpanel

import "encoding/json"

// BTPanelWebsiteResource 是可以安全上报到 anSSL 后端的脱敏宝塔网站资源。
type BTPanelWebsiteResource struct {
	TargetRef string   // TargetRef 是客户端生成的不透明稳定引用。
	Label     string   // Label 是网站备注或主域名。
	Domain    string   // Domain 是网站主域名。
	Domains   []string // Domains 是网站绑定的全部规范化域名。
	Protocol  string   // Protocol 是网站当前的 HTTP 或 HTTPS 状态。
	Status    string   // Status 是网站当前运行状态。
}

// btPanelWebsiteSummary 描述宝塔网站列表中的本地身份和展示字段。
type btPanelWebsiteSummary struct {
	ID      uint64          `json:"id"`      // ID 是仅保留在 deploy 本地的宝塔网站 ID。
	Name    string          `json:"name"`    // Name 是宝塔网站主名称，也是 SetSSL 的 siteName。
	Remark  string          `json:"rname"`   // Remark 是宝塔网站备注名称。
	Legacy  string          `json:"ps"`      // Legacy 兼容旧版宝塔网站备注字段。
	Status  json.RawMessage `json:"status"`  // Status 是兼容字符串或数字的启停状态。
	SSL     json.RawMessage `json:"ssl"`     // SSL 是网站列表中的证书启用标记。
	AddTime string          `json:"addtime"` // AddTime 用于区分删除后重新创建的网站。
}

// btPanelWebsitePage 描述宝塔数据查询接口的网站分页响应。
type btPanelWebsitePage struct {
	Data   []btPanelWebsiteSummary `json:"data"`   // Data 是当前页网站记录。
	Status *bool                   `json:"status"` // Status 在宝塔返回错误包络时为 false。
	Msg    string                  `json:"msg"`    // Msg 是错误包络中的本地诊断信息。
}

// btPanelWebsiteDomain 描述宝塔网站绑定的一个域名记录。
type btPanelWebsiteDomain struct {
	Name string `json:"name"` // Name 是可能带端口的域名或 IP 地址。
}

// btPanelWebsiteDomains 描述宝塔网站域名接口响应。
type btPanelWebsiteDomains struct {
	Domains []btPanelWebsiteDomain `json:"domains"` // Domains 是网站绑定域名列表。
	Status  *bool                  `json:"status"`  // Status 在宝塔返回错误包络时为 false。
	Msg     string                 `json:"msg"`     // Msg 是错误包络中的本地诊断信息。
}

// btPanelWebsiteSSL 描述宝塔网站当前证书和 HTTPS 状态。
type btPanelWebsiteSSL struct {
	Status      bool           `json:"status"`      // Status 表示网站是否已部署 SSL。
	HTTPToHTTPS bool           `json:"httpTohttps"` // HTTPToHTTPS 表示是否强制跳转 HTTPS。
	CertData    map[string]any `json:"cert_data"`   // CertData 是宝塔解析后的证书元数据，不含私钥。
}

// btPanelCertificateSummary 描述宝塔证书库中证书的脱敏元数据。
type btPanelCertificateSummary struct {
	ID      uint64                 `json:"id"`      // ID 是宝塔证书记录 ID，仅供面板内部使用。
	Hash    string                 `json:"hash"`    // Hash 是宝塔证书库的稳定摘要。
	Domains []string               `json:"dns"`     // Domains 是宝塔解析出的证书域名集合。
	Subject string                 `json:"subject"` // Subject 是证书主域名。
	Info    btPanelCertificateInfo `json:"info"`    // Info 是证书签发者和到期信息。
}

// btPanelCertificateInfo 描述宝塔证书库证书的有限元数据。
type btPanelCertificateInfo struct {
	Issuer   string `json:"issuer"`   // Issuer 是证书签发者名称。
	NotAfter string `json:"notAfter"` // NotAfter 是证书到期日期。
}

// btPanelCertificateSaveResponse 描述宝塔保存证书接口的响应。
type btPanelCertificateSaveResponse struct {
	Status  bool   `json:"status"`   // Status 表示保存是否成功。
	Msg     string `json:"msg"`      // Msg 是仅供 deploy 本地日志使用的诊断信息。
	SSLHash string `json:"ssl_hash"` // SSLHash 是新建或已存在证书的宝塔摘要。
}

// btPanelCertificateDetails 描述宝塔证书详情接口返回的本地证书内容。
type btPanelCertificateDetails struct {
	FullChain string `json:"fullchain"` // FullChain 是宝塔证书库中的完整证书链。
}

// btPanelActionResponse 描述宝塔写操作的统一成功状态。
type btPanelActionResponse struct {
	Status bool   `json:"status"` // Status 表示写操作是否成功。
	Msg    string `json:"msg"`    // Msg 是仅供 deploy 本地日志使用的诊断信息。
}

// btPanelWebsiteRecord 在 deploy 内部关联脱敏资源和真实宝塔网站身份。
type btPanelWebsiteRecord struct {
	ID       uint64                 // ID 是真实网站 ID，只能在 deploy 本地使用。
	SiteName string                 // SiteName 是宝塔 API 定位网站时使用的名称。
	Resource BTPanelWebsiteResource // Resource 是可以上报的脱敏资源。
}
