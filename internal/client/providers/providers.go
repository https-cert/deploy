package providers

// ProviderHandler 定义了所有提供商的通用接口
type ProviderHandler interface {
	// 测试连接
	TestConnection() (bool, error)

	// 上传证书
	UploadCertificate(name, domain, cert, key string) error

	// 部署到 对象存储
	DeployToOSS(certID string, domain string) (string, error)

	// 部署到 CDN
	DeployToCDN(certID string, domain string) (string, error)

	// 部署到 DCND
	DeployToDCND(certID string, domain string) (string, error)
}
