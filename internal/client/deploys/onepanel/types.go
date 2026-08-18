package onepanel

import "encoding/json"

// OnePanelAPIResponse 描述 1Panel v2 API 的统一响应外壳。
type OnePanelAPIResponse struct {
	Code    int             `json:"code"`    // Code 是 1Panel 业务状态码，200 表示成功。
	Message string          `json:"message"` // Message 是仅供 deploy 本地日志使用的诊断信息。
	Data    json.RawMessage `json:"data"`    // Data 是具体接口返回的数据。
}

// OnePanelWebsiteResource 是可以安全上报到 anSSL 后端的脱敏网站资源。
type OnePanelWebsiteResource struct {
	TargetRef string   // TargetRef 是客户端生成的不透明稳定引用。
	Label     string   // Label 是网站别名或主域名。
	Domain    string   // Domain 是网站主域名。
	Domains   []string // Domains 是网站绑定的全部规范化域名。
	Protocol  string   // Protocol 是安全展示的当前协议，仅用于判断首次 HTTPS 部署。
	Status    string   // Status 是安全展示的当前运行状态，仅用于阻止停止网站部署。
}

// onePanelWebsiteSummary 描述网站分页接口中生成资源引用所需的字段。
type onePanelWebsiteSummary struct {
	ID            uint64 `json:"id"`            // ID 是仅保留在 deploy 本地的 1Panel 网站 ID。
	CreatedAt     string `json:"createdAt"`     // CreatedAt 用于区分删除后重新创建的网站。
	Protocol      string `json:"protocol"`      // Protocol 表示网站是否已经启用 HTTPS。
	Status        string `json:"status"`        // Status 表示网站是否正在运行。
	PrimaryDomain string `json:"primaryDomain"` // PrimaryDomain 是 1Panel 网站主域名。
	Alias         string `json:"alias"`         // Alias 是网站展示别名。
}

// onePanelWebsitePage 描述网站分页数据。
type onePanelWebsitePage struct {
	Total int64                    `json:"total"` // Total 是当前查询的网站总数。
	Items []onePanelWebsiteSummary `json:"items"` // Items 是当前页网站。
}

// onePanelWebsiteDomain 描述 1Panel 网站绑定的一个域名记录。
type onePanelWebsiteDomain struct {
	Domain string `json:"domain"` // Domain 是可能带端口的域名或 IP 地址。
}

// onePanelWebsiteRecord 在 deploy 内部关联脱敏资源和真实网站 ID。
type onePanelWebsiteRecord struct {
	ID       uint64                  // ID 是真实网站 ID，只能在 deploy 本地使用。
	Resource OnePanelWebsiteResource // Resource 是可以上报的脱敏资源。
}

// onePanelWebsiteSSL 描述 HTTPS 配置当前绑定的证书。
type onePanelWebsiteSSL struct {
	PEM string `json:"pem"` // PEM 是当前网站证书链，仅用于本地指纹回读。
}

// onePanelWebsiteHTTPS 描述需要保留的 1Panel 网站 HTTPS 参数。
type onePanelWebsiteHTTPS struct {
	Enable                bool               `json:"enable"`                // Enable 表示网站当前是否启用 HTTPS。
	HTTPConfig            string             `json:"httpConfig"`            // HTTPConfig 是 HTTP 与 HTTPS 的跳转模式。
	SSL                   onePanelWebsiteSSL `json:"SSL"`                   // SSL 是网站当前绑定的证书。
	SSLProtocol           []string           `json:"SSLProtocol"`           // SSLProtocol 是启用的 TLS 协议列表。
	Algorithm             string             `json:"algorithm"`             // Algorithm 是 1Panel 保存的加密套件配置。
	HSTS                  bool               `json:"hsts"`                  // HSTS 表示是否启用严格传输安全。
	HSTSIncludeSubDomains bool               `json:"hstsIncludeSubDomains"` // HSTSIncludeSubDomains 表示 HSTS 是否覆盖子域名。
	HTTPSPorts            []int              `json:"httpsPorts"`            // HTTPSPorts 是网站当前 HTTPS 监听端口。
	HTTPSPort             string             `json:"httpsPort"`             // HTTPSPort 兼容旧版逗号分隔端口字段。
	HTTP3                 bool               `json:"http3"`                 // HTTP3 表示是否启用 HTTP/3。
}

// onePanelWebsiteHTTPSUpdate 是精确替换单个网站证书的请求体。
type onePanelWebsiteHTTPSUpdate struct {
	WebsiteID             uint64   `json:"websiteId"`             // WebsiteID 是目标网站 ID。
	Enable                bool     `json:"enable"`                // Enable 保持网站 HTTPS 开启。
	WebsiteSSLID          uint64   `json:"websiteSSLId"`          // WebsiteSSLID 在手动证书模式下保持为零。
	Type                  string   `json:"type"`                  // Type 固定为 manual，避免修改共享证书记录。
	PrivateKey            string   `json:"privateKey"`            // PrivateKey 是本次部署的私钥。
	Certificate           string   `json:"certificate"`           // Certificate 是本次部署的完整证书链。
	PrivateKeyPath        string   `json:"privateKeyPath"`        // PrivateKeyPath 在粘贴模式下为空。
	CertificatePath       string   `json:"certificatePath"`       // CertificatePath 在粘贴模式下为空。
	ImportType            string   `json:"importType"`            // ImportType 固定为 paste。
	HTTPConfig            string   `json:"httpConfig"`            // HTTPConfig 保留网站原有跳转模式。
	SSLProtocol           []string `json:"SSLProtocol"`           // SSLProtocol 保留网站原有 TLS 协议。
	Algorithm             string   `json:"algorithm"`             // Algorithm 保留网站原有加密套件。
	HSTS                  bool     `json:"hsts"`                  // HSTS 保留网站原有设置。
	HSTSIncludeSubDomains bool     `json:"hstsIncludeSubDomains"` // HSTSIncludeSubDomains 保留网站原有设置。
	HTTPSPorts            []int    `json:"httpsPorts"`            // HTTPSPorts 保留网站原有监听端口。
	HTTP3                 bool     `json:"http3"`                 // HTTP3 保留网站原有设置。
}

// onePanelRequestError 保存仅供 deploy 本地判断重试属性的 API 错误。
type onePanelRequestError struct {
	Retryable bool  // Retryable 表示网络或服务端错误可以稍后重试。
	Cause     error // Cause 不得写入 WebSocket 响应；在线日志必须先经过统一脱敏。
}

// Error 返回 1Panel 本地诊断信息。
func (e *onePanelRequestError) Error() string {
	if e == nil || e.Cause == nil {
		return "1Panel 请求失败"
	}
	return e.Cause.Error()
}

// Unwrap 返回原始错误，供 errors.Is 和 errors.As 使用。
func (e *onePanelRequestError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}
