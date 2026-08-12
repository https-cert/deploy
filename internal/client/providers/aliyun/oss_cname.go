package aliyun

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// newSignedOSSCnameAPI 创建生产 OSS CNAME 适配器。
func newSignedOSSCnameAPI(accessKeyID, accessKeySecret string, httpClient ossHTTPClient) ossCnameAPI {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &signedOSSCnameAPI{
		AccessKeyID:     strings.TrimSpace(accessKeyID),
		AccessKeySecret: strings.TrimSpace(accessKeySecret),
		HTTPClient:      httpClient,
		Now:             time.Now,
	}
}

// ListBuckets 查询当前凭据可见的全部 OSS Bucket。
func (a *signedOSSCnameAPI) ListBuckets(ctx context.Context) ([]ossBucketRecord, error) {
	if a == nil || a.HTTPClient == nil || strings.TrimSpace(a.AccessKeyID) == "" || strings.TrimSpace(a.AccessKeySecret) == "" {
		return nil, &cloudAPIError{Message: "OSS Bucket 目录客户端未初始化"}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://oss.aliyuncs.com/", nil)
	if err != nil {
		return nil, &cloudAPIError{Message: "OSS Bucket 目录请求构造失败", Cause: err}
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	date := now.Format(http.TimeFormat)
	request.Header.Set("Date", date)
	request.Header.Set("Authorization", ossAuthorization(a.AccessKeyID, a.AccessKeySecret, http.MethodGet, "", "", date, "/"))
	response, err := a.HTTPClient.Do(request)
	if err != nil {
		return nil, &cloudAPIError{Message: "OSS Bucket 目录网络请求失败", Cause: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxOSSResponseBodySize+1))
	if err != nil || len(body) > maxOSSResponseBodySize {
		return nil, &cloudAPIError{StatusCode: response.StatusCode, RequestID: ossRequestID(response.Header), Message: "OSS Bucket 目录响应读取失败", Cause: err}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var responseError ossErrorXML
		_ = xml.Unmarshal(body, &responseError)
		return nil, &cloudAPIError{
			StatusCode: response.StatusCode,
			Code:       strings.TrimSpace(responseError.Code),
			RequestID:  firstNonEmpty(ossRequestID(response.Header), responseError.RequestID),
			Message:    "OSS Bucket 目录请求失败",
		}
	}
	var decoded ossListBucketsResultXML
	if err := xml.Unmarshal(body, &decoded); err != nil {
		return nil, &cloudAPIError{RequestID: ossRequestID(response.Header), Message: "OSS Bucket 目录响应格式异常", Cause: err}
	}
	result := make([]ossBucketRecord, 0, len(decoded.Buckets))
	for _, bucket := range decoded.Buckets {
		region := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(bucket.Location)), "oss-")
		if strings.TrimSpace(bucket.Name) == "" || region == "" {
			continue
		}
		result = append(result, ossBucketRecord{Name: strings.TrimSpace(bucket.Name), Region: region, CreatedAt: strings.TrimSpace(bucket.CreationDate)})
	}
	return result, nil
}

// ListCname 查询一个 Bucket 的 CNAME 列表并保留响应 request ID。
func (a *signedOSSCnameAPI) ListCname(ctx context.Context, target providers.DeploymentResource) (ossCnameListResult, error) {
	body, requestID, err := a.execute(ctx, http.MethodGet, target, "cname", nil)
	if err != nil {
		return ossCnameListResult{}, err
	}
	var decoded ossListCnameResultXML
	if err := xml.Unmarshal(body, &decoded); err != nil {
		return ossCnameListResult{}, &cloudAPIError{
			RequestID: requestID,
			Message:   "OSS ListCname 响应格式异常",
			Cause:     err,
		}
	}
	records := make([]ossCnameRecord, 0, len(decoded.Cnames))
	for _, cname := range decoded.Cnames {
		records = append(records, ossCnameRecord{
			Domain: cname.Domain,
			Status: cname.Status,
			Certificate: ossCnameCertificate{
				CertificateID: cname.Certificate.CertificateID,
				Fingerprint:   cname.Certificate.Fingerprint,
				Status:        cname.Certificate.Status,
			},
		})
	}
	return ossCnameListResult{
		Bucket:    decoded.Bucket,
		Records:   records,
		RequestID: requestID,
	}, nil
}

// PutCname 通过 OSS CNAME API 更新一个自定义域名的证书配置。
func (a *signedOSSCnameAPI) PutCname(ctx context.Context, request ossCnamePutRequest) (ossCnamePutResult, error) {
	configuration := ossCertificateConfigurationXML{
		Certificate:    request.CertificatePEM,
		PrivateKey:     request.PrivateKeyPEM,
		PreviousCertID: strings.TrimSpace(request.PreviousCertificateID),
	}
	if request.Force {
		force := true
		configuration.Force = &force
	}
	payload, err := xml.Marshal(ossBucketCnameConfigurationXML{
		Cname: ossCnameXML{
			Domain:                   request.Target.Domain,
			CertificateConfiguration: configuration,
		},
	})
	if err != nil {
		return ossCnamePutResult{}, &cloudAPIError{Message: "OSS PutCname 请求编码失败", Cause: err}
	}
	_, requestID, err := a.execute(ctx, http.MethodPost, request.Target, "cname&comp=add", payload)
	if err != nil {
		return ossCnamePutResult{}, err
	}
	return ossCnamePutResult{RequestID: requestID}, nil
}

// execute 构造、签名并发送一条精确 Bucket CNAME 请求。
func (a *signedOSSCnameAPI) execute(ctx context.Context, method string, target providers.DeploymentResource, rawQuery string, payload []byte) ([]byte, string, error) {
	if a == nil || a.HTTPClient == nil {
		return nil, "", &cloudAPIError{Message: "OSS CNAME 客户端未初始化"}
	}
	if strings.TrimSpace(a.AccessKeyID) == "" || strings.TrimSpace(a.AccessKeySecret) == "" {
		return nil, "", &cloudAPIError{Message: "OSS CNAME 访问凭据不完整"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	requestURL, canonicalResource, err := buildOSSRequestURL(target, rawQuery)
	if err != nil {
		return nil, "", &cloudAPIError{Message: "OSS CNAME endpoint 配置无效", Cause: err}
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(payload))
	if err != nil {
		return nil, "", &cloudAPIError{Message: "OSS CNAME 请求构造失败", Cause: err}
	}

	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	date := now.Format(http.TimeFormat)
	contentType := "application/xml"
	contentMD5 := ""
	if len(payload) > 0 {
		digest := md5.Sum(payload)
		contentMD5 = base64.StdEncoding.EncodeToString(digest[:])
		request.Header.Set("Content-MD5", contentMD5)
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Date", date)
	request.Header.Set("Authorization", ossAuthorization(a.AccessKeyID, a.AccessKeySecret, method, contentMD5, contentType, date, canonicalResource))

	response, err := a.HTTPClient.Do(request)
	if err != nil {
		return nil, "", &cloudAPIError{Message: "OSS CNAME 网络请求失败", Cause: err}
	}
	defer response.Body.Close()
	requestIDFromHeader := ossRequestID(response.Header)
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxOSSResponseBodySize+1))
	if err != nil {
		return nil, requestIDFromHeader, &cloudAPIError{
			StatusCode: response.StatusCode,
			RequestID:  requestIDFromHeader,
			Message:    "OSS CNAME 响应读取失败",
			Cause:      err,
		}
	}
	if len(responseBody) > maxOSSResponseBodySize {
		return nil, requestIDFromHeader, &cloudAPIError{
			StatusCode: response.StatusCode,
			RequestID:  requestIDFromHeader,
			Message:    "OSS CNAME 响应过大",
		}
	}
	requestID := requestIDFromHeader
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var responseError ossErrorXML
		_ = xml.Unmarshal(responseBody, &responseError)
		requestID = firstNonEmpty(requestID, responseError.RequestID)
		return nil, requestID, &cloudAPIError{
			StatusCode: response.StatusCode,
			Code:       strings.TrimSpace(responseError.Code),
			RequestID:  requestID,
			Message:    "OSS CNAME API 请求失败",
		}
	}
	return responseBody, requestID, nil
}

// ossRequestID 以大小写不敏感的方式读取 OSS 请求编号头。
func ossRequestID(headers http.Header) string {
	for key, values := range headers {
		if !strings.EqualFold(key, "x-oss-request-id") || len(values) == 0 {
			continue
		}
		if requestID := strings.TrimSpace(values[0]); requestID != "" {
			return requestID
		}
	}
	return ""
}

// buildOSSRequestURL 创建虚拟主机形式的 OSS URL 和签名所需的 canonical resource。
func buildOSSRequestURL(target providers.DeploymentResource, rawQuery string) (string, string, error) {
	endpoint := strings.TrimSpace(target.Endpoint)
	if endpoint == "" {
		region := strings.TrimSpace(target.Region)
		if region == "" {
			return "", "", fmt.Errorf("缺少 OSS region")
		}
		endpoint = "https://oss-" + region + ".aliyuncs.com"
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(parsedEndpoint.Scheme, "https") || parsedEndpoint.Host == "" {
		return "", "", fmt.Errorf("OSS endpoint 必须是 HTTPS origin")
	}
	if parsedEndpoint.User != nil || parsedEndpoint.Path != "" || parsedEndpoint.RawQuery != "" || parsedEndpoint.Fragment != "" {
		return "", "", fmt.Errorf("OSS endpoint 包含不允许的附加部分")
	}
	bucket := strings.TrimSpace(target.Bucket)
	if bucket == "" {
		return "", "", fmt.Errorf("缺少 OSS Bucket")
	}
	lowerHost := strings.ToLower(parsedEndpoint.Hostname())
	if !strings.HasPrefix(lowerHost, strings.ToLower(bucket)+".") {
		parsedEndpoint.Host = bucket + "." + parsedEndpoint.Host
	}
	parsedEndpoint.Path = "/"
	parsedEndpoint.RawQuery = rawQuery
	return parsedEndpoint.String(), "/" + bucket + "/?" + rawQuery, nil
}

// ossAuthorization 生成 OSS Signature V1 Authorization 头。
func ossAuthorization(accessKeyID, accessKeySecret, method, contentMD5, contentType, date, canonicalResource string) string {
	stringToSign := strings.Join([]string{method, contentMD5, contentType, date, canonicalResource}, "\n")
	mac := hmac.New(sha1.New, []byte(accessKeySecret))
	_, _ = mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return "OSS " + accessKeyID + ":" + signature
}

// deployOSS 部署证书到一个精确的 OSS Bucket 自定义域名。
func (p *Provider) deployOSS(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	if p == nil || p.ossAPI == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 客户端未初始化", false, "", nil)
	}
	preflight, err := p.ossAPI.ListCname(ctx, target)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取 OSS 自定义域名", err)
	}
	if strings.TrimSpace(preflight.Bucket) != "" && !strings.EqualFold(strings.TrimSpace(preflight.Bucket), strings.TrimSpace(target.Bucket)) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 目标校验失败", false, preflight.RequestID, newSafeAliyunCause("目标校验", fmt.Errorf("Bucket 与响应不一致")))
	}
	record, found := findExactOSSCname(preflight.Records, target.Domain)
	if !found {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 目标校验失败", false, preflight.RequestID, newSafeAliyunCause("目标校验", fmt.Errorf("未找到精确自定义域名")))
	}

	fingerprint, err := certificateSHA1Fingerprint(certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 证书校验失败", false, preflight.RequestID, newSafeAliyunCause("证书指纹", err))
	}
	if ossFingerprintMatches(record.Certificate.Fingerprint, fingerprint) && strings.EqualFold(strings.TrimSpace(record.Certificate.Status), "enabled") {
		return providers.DeploymentResult{
			RequestID: preflight.RequestID,
			Message:   "阿里云 OSS 自定义域名已配置当前证书",
		}, nil
	}

	previousCertificateID := strings.TrimSpace(record.Certificate.CertificateID)
	written, err := p.ossAPI.PutCname(ctx, ossCnamePutRequest{
		Target:                target,
		CertificatePEM:        certificate.CertificatePEM,
		PrivateKeyPEM:         certificate.PrivateKeyPEM,
		PreviousCertificateID: previousCertificateID,
		Force:                 previousCertificateID == "",
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("更新 OSS 自定义域名证书", err)
	}

	readback, err := p.ossAPI.ListCname(ctx, target)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("回读 OSS 自定义域名证书", written.RequestID, err)
	}
	readbackRecord, found := findExactOSSCname(readback.Records, target.Domain)
	if !found {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 控制面未返回目标域名", true, firstNonEmpty(written.RequestID, readback.RequestID), nil)
	}
	certificateStatus := strings.ToLower(strings.TrimSpace(readbackRecord.Certificate.Status))
	if ossFingerprintMatches(readbackRecord.Certificate.Fingerprint, fingerprint) && certificateStatus == "enabled" {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
			Message:   "阿里云 OSS 自定义域名证书部署成功",
		}, nil
	}
	if isApplyingStatus(certificateStatus, readbackRecord.Status) {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
			Message:   "阿里云 OSS 自定义域名证书已提交，控制面正在应用",
		}, nil
	}
	return providers.DeploymentResult{}, providers.NewDeploymentError(
		"阿里云 OSS 控制面尚未确认新证书",
		true,
		firstNonEmpty(written.RequestID, readback.RequestID),
		newSafeAliyunCause("控制面回读", fmt.Errorf("证书指纹或状态未确认")),
	)
}

// findExactOSSCname 查找唯一的精确自定义域名，拒绝重复或模糊匹配。
func findExactOSSCname(records []ossCnameRecord, targetDomain string) (ossCnameRecord, bool) {
	var matched ossCnameRecord
	found := false
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSpace(record.Domain), strings.TrimSpace(targetDomain)) {
			continue
		}
		if found {
			return ossCnameRecord{}, false
		}
		matched = record
		found = true
	}
	return matched, found
}

// certificateSHA1Fingerprint 提取 OSS ListCname 使用的叶证书 SHA-1 指纹。
func certificateSHA1Fingerprint(certificatePEM string) (string, error) {
	rest := []byte(certificatePEM)
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if !strings.EqualFold(strings.TrimSpace(block.Type), "CERTIFICATE") {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("解析证书失败: %w", err)
		}
		digest := sha1.Sum(certificate.Raw)
		return fmt.Sprintf("%x", digest[:]), nil
	}
	return "", fmt.Errorf("证书内容中未找到 CERTIFICATE 块")
}

// ossFingerprintMatches 兼容 OSS 返回带冒号或部分掩码的 SHA-1 指纹。
func ossFingerprintMatches(actual, expected string) bool {
	normalizedActual := normalizeComparableToken(actual)
	normalizedExpected := normalizeComparableToken(expected)
	if normalizedActual == "" || normalizedExpected == "" {
		return false
	}
	if normalizedActual == normalizedExpected {
		return true
	}
	return len(normalizedActual) >= 24 && strings.HasPrefix(normalizedExpected, normalizedActual)
}
