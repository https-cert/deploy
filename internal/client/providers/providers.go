package providers

import (
	"context"

	"github.com/https-cert/deploy/pb/deployPB"
)

// ResourceCatalogResult 描述一个明确云业务的实时脱敏资源目录。
type ResourceCatalogResult struct {
	Resources []DeploymentResource              // Resources 是成功发现且可安全上报的资源。
	Status    deployPB.DeploymentResourceStatus // Status 是完整、部分或失败等目录状态。
	Error     error                             // Error 是诊断详情；在线展示必须先经过日志脱敏层。
}

// ResourceDiscoverer 统一云资源的实时发现、引用解析和只读连接测试。
type ResourceDiscoverer interface {
	// DiscoverResources 实时读取指定部署类型下的全部可识别资源。
	DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) ResourceCatalogResult
	// ResolveResource 实时读取目录并按不透明引用唯一解析资源。
	ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (DeploymentResource, error)
	// TestResource 确认资源仍存在、可读且具备精确证书部署条件。
	TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error
}

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
	// DeployCertificate 将证书部署到指定 v2 部署类型对应的精确资源。
	DeployCertificate(ctx context.Context, certificate CertificateMaterial, deploymentType deployPB.DeploymentType, resource DeploymentResource) (DeploymentResult, error)
}

// DeploymentResourceProvider 组合动态发现、解析、测试和精确部署能力。
type DeploymentResourceProvider interface {
	ResourceDiscoverer
	DeploymentResourceDeployer
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
	TargetRef      string                                  // TargetRef 客户端根据资源身份自动生成的不透明稳定引用。
	Label          string                                  // Label 本地展示名称。
	Domain         string                                  // Domain 实际绑定证书的域名。
	Domains        []string                                // Domains 是资源当前绑定的全部规范化域名。
	Group          string                                  // Group 是站点、Bucket 或负载均衡实例的脱敏展示名称。
	Region         string                                  // Region 云资源所在地域。
	Protocol       string                                  // Protocol 是资源当前使用的公开协议名称。
	Status         string                                  // Status 是云端返回的脱敏运行状态。
	Availability   deployPB.DeploymentResourceAvailability // Availability 是资源是否可测试和部署的结构化状态。
	Endpoint       string                                  // Endpoint OSS endpoint 覆盖值。
	Bucket         string                                  // Bucket 对象存储 Bucket。
	SiteID         string                                  // SiteID 阿里云 ESA Site ID。
	ZoneID         string                                  // ZoneID 腾讯云 EdgeOne Zone ID。
	LoadBalancerID string                                  // LoadBalancerID 负载均衡实例 ID。
	ListenerPort   int                                     // ListenerPort 负载均衡监听端口。
	ListenerID     string                                  // ListenerID 腾讯云 CLB 或阿里云 ALB/NLB 监听器 ID。
	ResourceID     string                                  // ResourceID 是仅供 deploy 本地解析的云资源稳定身份，不得上报。
	CreatedAt      string                                  // CreatedAt 用于区分删除后重建的同名资源，不得上报。
}

// DeploymentResult 描述云 API 接受部署后的脱敏诊断信息。
type DeploymentResult struct {
	RequestID string // RequestID 云厂商请求 ID。
	Message   string // Message 不包含凭据或敏感资源定位参数的结果说明。
}
