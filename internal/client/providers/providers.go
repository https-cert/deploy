package providers

import (
	"context"

	"github.com/https-cert/deploy/pb/deployPB"
)

// ConnectionTester 测试云厂商凭据是否可以访问对应控制面。
type ConnectionTester interface {
	TestConnection() (bool, error)
}

// CertificateUploader 将证书上传到云厂商证书中心。
type CertificateUploader interface {
	UploadCertificate(name, domain, cert, key string) error
}

// ProviderHandler 组合证书中心上传业务所需的连接测试和证书上传能力。
type ProviderHandler interface {
	ConnectionTester
	CertificateUploader
}

// DeploymentResourceDeployer 将证书部署到一个明确业务下已经精确解析的资源。
type DeploymentResourceDeployer interface {
	DeployCertificate(ctx context.Context, certificate CertificateMaterial, business deployPB.ExecuteBusinesType, resource DeploymentResource) (DeploymentResult, error)
}

// CertificateMaterial 封装云部署使用的证书材料。
type CertificateMaterial struct {
	Name           string // Name 云厂商证书备注或别名。
	Domain         string // Domain 证书申请主域名，仅用于展示和兼容旧业务。
	CertificatePEM string // CertificatePEM 完整 PEM 证书链。
	PrivateKeyPEM  string // PrivateKeyPEM PEM 私钥。
}

// DeploymentResource 描述从明确业务配置中精确解析出的部署资源。
type DeploymentResource struct {
	TargetRef string // TargetRef 客户端根据资源身份自动生成的不透明稳定引用。
	Label     string // Label 本地展示名称。
	Domain    string // Domain 实际绑定证书的域名。
	Region    string // Region 对象存储地域。
	Endpoint  string // Endpoint OSS endpoint 覆盖值。
	Bucket    string // Bucket 对象存储 Bucket。
	SiteID    string // SiteID 阿里云 ESA Site ID。
	ZoneID    string // ZoneID 腾讯云 EdgeOne Zone ID。
}

// DeploymentResult 描述云 API 接受部署后的脱敏诊断信息。
type DeploymentResult struct {
	RequestID string // RequestID 云厂商请求 ID。
	Message   string // Message 不包含凭据或敏感资源定位参数的结果说明。
}
