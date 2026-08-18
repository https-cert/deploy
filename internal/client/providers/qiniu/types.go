package qiniu

// authorizationMode selects the Qiniu authentication scheme required by an endpoint.
type authorizationMode int

const (
	// authorizationQBox signs certificate API requests with QBox credentials.
	authorizationQBox authorizationMode = iota
	// authorizationQiniuV2 signs domain API requests with Qiniu V2 credentials.
	authorizationQiniuV2
)

// apiResponse is the bounded, decoded-independent response used by provider operations.
type apiResponse struct {
	// StatusCode is the HTTP status received from Qiniu.
	StatusCode int
	// ProviderRequestID is Qiniu's request identifier.
	ProviderRequestID string
	// Body is the original response body after size validation.
	Body []byte
}

// certificateUploadRequest is the exact lowercase JSON schema expected by fusion.qiniuapi.com/sslcert.
type certificateUploadRequest struct {
	// Name is Qiniu's human-readable certificate name.
	Name string `json:"name"`
	// PrivateKey is the PEM private key sent as pri.
	PrivateKey string `json:"pri"`
	// Certificate is the PEM certificate chain sent as ca.
	Certificate string `json:"ca"`
}

// certificateUploadResponse is the minimal response required from the Qiniu certificate API.
type certificateUploadResponse struct {
	// CertificateID is Qiniu's certID value.
	CertificateID string `json:"certID"`
}

// httpsConfigurationRequest is the minimal update schema that preserves all unrelated domain HTTPS settings.
type httpsConfigurationRequest struct {
	// CertificateID is the Qiniu certID to bind to the exact domain.
	CertificateID string `json:"certId"`
}

// domainHTTPSConfig contains the certificate identifier returned by the domain read API.
type domainHTTPSConfig struct {
	// CertificateID is the current HTTPS certId configured for the domain.
	CertificateID string `json:"certId"`
}

// domainInfo contains the fields used to validate and read back one exact Qiniu domain.
type domainInfo struct {
	// Name is the custom domain name returned by Qiniu.
	Name string `json:"name"`
	// Product identifies the Qiniu CDN product that owns the domain.
	Product string `json:"product"`
	// Protocol is the enabled protocol configuration reported by Qiniu.
	Protocol string `json:"protocol"`
	// OperatingState 是域名控制面操作状态。
	OperatingState string `json:"operatingState"`
	// CreateAt 是域名首次创建时间，用于区分删除后重建的同名域名。
	CreateAt string `json:"createAt"`
	// HTTPS contains the currently configured custom certificate identifier.
	HTTPS domainHTTPSConfig `json:"https"`
}

// domainSummary 是七牛域名列表返回的最小字段集合。
type domainSummary struct {
	// Name 是需要继续读取详情的加速域名。
	Name string `json:"name"`
}

// domainListResponse 是七牛账户域名分页响应。
type domainListResponse struct {
	// Domains 是当前页域名摘要。
	Domains []domainSummary `json:"domains"`
	// Marker 是下一页游标，空值表示目录结束。
	Marker string `json:"marker"`
}
