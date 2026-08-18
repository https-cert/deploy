package aliyun

import (
	"context"
	"encoding/xml"
	"net/http"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
)

const maxOSSResponseBodySize = 1024 * 1024

// ossHTTPClient 是 OSS 适配器实际使用的最小 HTTP 客户端接口。
type ossHTTPClient interface {
	// Do 发送一条已签名且带 context 的 OSS 请求。
	Do(request *http.Request) (*http.Response, error)
}

// ossCnameAPI 隔离 OSS CNAME 控制面，便于测试 PreviousCertId 和 Force 行为。
type ossCnameAPI interface {
	// ListBuckets 返回账户下的 Bucket 目录。
	ListBuckets(ctx context.Context) ([]ossBucketRecord, error)
	// ListCname 返回 Bucket 中所有自定义域名，由上层执行精确匹配。
	ListCname(ctx context.Context, target providers.DeploymentResource) (ossCnameListResult, error)
	// PutCname 为一个已经过预检的自定义域名提交证书和私钥。
	PutCname(ctx context.Context, request ossCnamePutRequest) (ossCnamePutResult, error)
}

// ossBucketRecord 描述 OSS Bucket 的稳定身份和地域。
type ossBucketRecord struct {
	Name      string // Name 是 Bucket 名称，仅在 deploy 本地使用。
	Region    string // Region 是 Bucket 地域。
	CreatedAt string // CreatedAt 用于区分删除后重建的同名 Bucket。
}

// ossCnameCertificate 保存 OSS CNAME 控制面返回的证书元数据。
type ossCnameCertificate struct {
	// CertificateID 是当前绑定证书 ID，仅用于 PreviousCertId 乐观并发控制。
	CertificateID string
	// Fingerprint 是当前证书指纹，用于回读确认。
	Fingerprint string
	// Status 是当前证书控制面状态。
	Status string
}

// ossCnameRecord 描述一个 Bucket 中的精确 CNAME 记录。
type ossCnameRecord struct {
	// Domain 是自定义域名。
	Domain string
	// Status 是 CNAME 记录状态。
	Status string
	// Certificate 是该 CNAME 当前的证书信息。
	Certificate ossCnameCertificate
}

// ossCnameListResult 是 ListCname 的最小业务结果。
type ossCnameListResult struct {
	// Bucket 是服务端返回的 Bucket 名称，用于防止错误 endpoint 造成跨资源写入。
	Bucket string
	// Records 是该 Bucket 的 CNAME 记录列表。
	Records []ossCnameRecord
	// RequestID 是 OSS 请求编号。
	RequestID string
}

// ossCnamePutRequest 描述一次只针对单个 Bucket 自定义域名的证书更新。
type ossCnamePutRequest struct {
	// Target 是已经完成静态校验的 OSS 部署资源。
	Target providers.DeploymentResource
	// CertificatePEM 是要绑定的 PEM 证书链。
	CertificatePEM string
	// PrivateKeyPEM 是与证书匹配的 PEM 私钥。
	PrivateKeyPEM string
	// PreviousCertificateID 是已有证书 ID，存在时用于避免覆盖并发更新。
	PreviousCertificateID string
	// Force 仅在自定义域名首次绑定证书时为 true。
	Force bool
}

// ossCnamePutResult 保存 OSS 写请求的脱敏元数据。
type ossCnamePutResult struct {
	// RequestID 是 OSS 写请求编号。
	RequestID string
}

// signedOSSCnameAPI 使用 OSS Signature V1 实现可取消的 CNAME 证书读写。
// 签名字符串与 HTTP 请求由同一适配器生成，避免测试与实际发送内容不一致。
type signedOSSCnameAPI struct {
	// AccessKeyID 是 OSS 签名所需的访问密钥标识，不得写入日志。
	AccessKeyID string
	// AccessKeySecret 是 OSS 签名所需的访问密钥密钥，不得写入日志。
	AccessKeySecret string
	// HTTPClient 发送带 context 的 HTTP 请求。
	HTTPClient ossHTTPClient
	// Now 提供 HTTP Date，测试可注入固定时间。
	Now func() time.Time
}

// ossBucketCnameConfigurationXML 是 PutCname 请求的 XML 根节点。
type ossBucketCnameConfigurationXML struct {
	// XMLName 固定根节点名称。
	XMLName xml.Name `xml:"BucketCnameConfiguration"`
	// Cname 是本次唯一要更新的自定义域名。
	Cname ossCnameXML `xml:"Cname"`
}

// ossCnameXML 是 PutCname XML 中的单项 CNAME 配置。
type ossCnameXML struct {
	// Domain 是精确自定义域名。
	Domain string `xml:"Domain"`
	// CertificateConfiguration 是上传证书配置。
	CertificateConfiguration ossCertificateConfigurationXML `xml:"CertificateConfiguration"`
}

// ossCertificateConfigurationXML 是 OSS CNAME 上传证书的 XML 结构。
type ossCertificateConfigurationXML struct {
	// Certificate 是完整 PEM 证书链。
	Certificate string `xml:"Certificate"`
	// PrivateKey 是 PEM 私钥。
	PrivateKey string `xml:"PrivateKey"`
	// PreviousCertID 是已有证书 ID，空值时不输出。
	PreviousCertID string `xml:"PreviousCertId,omitempty"`
	// Force 在首次绑定证书时显式输出 true，更新已有证书时不输出。
	Force *bool `xml:"Force,omitempty"`
}

// ossListCnameResultXML 是 OSS ListCname 响应的 XML 结构。
type ossListCnameResultXML struct {
	// Bucket 是响应所属 Bucket。
	Bucket string `xml:"Bucket"`
	// Cnames 是 Bucket 中的全部 CNAME 记录。
	Cnames []ossCnameInfoXML `xml:"Cname"`
}

// ossCnameInfoXML 是 ListCname 返回的单项自定义域名。
type ossCnameInfoXML struct {
	// Domain 是自定义域名。
	Domain string `xml:"Domain"`
	// Status 是 CNAME 状态。
	Status string `xml:"Status"`
	// Certificate 是当前证书配置。
	Certificate ossCnameCertificateXML `xml:"Certificate"`
}

// ossCnameCertificateXML 是 ListCname 返回的证书详情。
type ossCnameCertificateXML struct {
	// CertificateID 是当前证书 ID。
	CertificateID string `xml:"CertId"`
	// Fingerprint 是当前证书 SHA-1 指纹。
	Fingerprint string `xml:"Fingerprint"`
	// Status 是证书状态。
	Status string `xml:"Status"`
}

// ossErrorXML 是 OSS 错误响应中允许读取的脱敏字段。
type ossErrorXML struct {
	// Code 是 OSS 错误码。
	Code string `xml:"Code"`
	// RequestID 是 OSS 请求编号。
	RequestID string `xml:"RequestId"`
}

// ossListBucketsResultXML 是 OSS 服务级 Bucket 列表响应。
type ossListBucketsResultXML struct {
	Buckets []ossBucketXML `xml:"Buckets>Bucket"` // Buckets 是账户下的 Bucket 记录。
}

// ossBucketXML 是 OSS 服务级目录中的单个 Bucket。
type ossBucketXML struct {
	Name         string `xml:"Name"`         // Name 是 Bucket 名称。
	Location     string `xml:"Location"`     // Location 是 OSS endpoint 地域名。
	CreationDate string `xml:"CreationDate"` // CreationDate 是 Bucket 创建时间。
}
