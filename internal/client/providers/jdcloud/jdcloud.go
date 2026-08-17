// Package jdcloud implements JD Cloud certificate-center upload and CDN deployment.
package jdcloud

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/jdcloud-api/jdcloud-sdk-go/core"
	cdnapi "github.com/jdcloud-api/jdcloud-sdk-go/services/cdn/apis"
	cdnclient "github.com/jdcloud-api/jdcloud-sdk-go/services/cdn/client"
	sslapi "github.com/jdcloud-api/jdcloud-sdk-go/services/ssl/apis"
	sslclient "github.com/jdcloud-api/jdcloud-sdk-go/services/ssl/client"
)

const (
	resourcePageSize = 50
	resourceMaxPages = 100
	resourceMaxCount = 10000
	taskPollAttempts = 20
	taskPollInterval = 500 * time.Millisecond
)

var (
	_ providers.ProviderHandler            = (*Provider)(nil)
	_ providers.DeploymentResourceProvider = (*Provider)(nil)
)

// cdnClient 是京东云 CDN 资源和配置操作所需的最小官方 SDK 接口。
type cdnClient interface {
	GetDomainList(request *cdnapi.GetDomainListRequest) (*cdnapi.GetDomainListResponse, error)
	GetDomainDetail(request *cdnapi.GetDomainDetailRequest) (*cdnapi.GetDomainDetailResponse, error)
	SetHttpType(request *cdnapi.SetHttpTypeRequest) (*cdnapi.SetHttpTypeResponse, error)
	QueryDomainConfigStatus(request *cdnapi.QueryDomainConfigStatusRequest) (*cdnapi.QueryDomainConfigStatusResponse, error)
}

// certificateClient 是京东云 SSL 证书上传和回读所需的最小官方 SDK 接口。
type certificateClient interface {
	UploadCert(request *sslapi.UploadCertRequest) (*sslapi.UploadCertResponse, error)
	DescribeCert(request *sslapi.DescribeCertRequest) (*sslapi.DescribeCertResponse, error)
	DescribeCerts(request *sslapi.DescribeCertsRequest) (*sslapi.DescribeCertsResponse, error)
}

// Provider 保存京东云访问密钥和官方 SDK 客户端。
type Provider struct {
	accessKey         string            // accessKey 是京东云 Access Key ID。
	secretKey         string            // secretKey 是京东云 Secret Access Key。
	cdnClient         cdnClient         // cdnClient 负责 CDN 域名和配置操作。
	certificateClient certificateClient // certificateClient 负责 SSL 证书中心操作。
	pollInterval      time.Duration     // pollInterval 是异步配置任务的轮询间隔。
}

// apiError 保存京东云业务响应中的错误分类和请求 ID。
type apiError struct {
	Operation string // Operation 是失败的控制面操作。
	Code      int    // Code 是京东云业务错误码。
	Status    string // Status 是京东云业务错误状态。
	RequestID string // RequestID 是京东云请求 ID。
	Retryable bool   // Retryable 表示请求是否适合自动重试。
	Cause     error  // Cause 保存传输或解析错误。
}

// Error 返回不包含凭据和资源明文的京东云错误。
func (e *apiError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != 0 {
		return fmt.Sprintf("京东云 %s 失败: code=%d", e.Operation, e.Code)
	}
	return "京东云 " + e.Operation + " 失败"
}

// Unwrap 暴露底层错误供 errors.Is 和 errors.As 使用。
func (e *apiError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// New 创建使用京东云生产 HTTPS Endpoint 的 provider。
func New(accessKey, secretKey string) *Provider {
	credential := core.NewCredentials(strings.TrimSpace(accessKey), strings.TrimSpace(secretKey))
	cdn := cdnclient.NewCdnClient(credential)
	certificate := sslclient.NewSslClient(credential)
	cdn.DisableLogger()
	certificate.DisableLogger()
	return newWithClients(accessKey, secretKey, cdn, certificate)
}

// newWithClients 创建支持单元测试注入的京东云 provider。
func newWithClients(accessKey, secretKey string, cdn cdnClient, certificate certificateClient) *Provider {
	return &Provider{
		accessKey:         strings.TrimSpace(accessKey),
		secretKey:         strings.TrimSpace(secretKey),
		cdnClient:         cdn,
		certificateClient: certificate,
		pollInterval:      taskPollInterval,
	}
}

// TestConnection 验证京东云凭据可以读取 CDN 域名目录。
func (p *Provider) TestConnection() (bool, error) {
	if err := p.validateCredentials(); err != nil {
		return false, err
	}
	if p.cdnClient == nil {
		return false, providers.NewDeploymentError("京东云 CDN 客户端未初始化", false, "", nil)
	}
	request := cdnapi.NewGetDomainListRequest()
	request.SetPageNumber(1)
	request.SetPageSize(1)
	response, err := p.cdnClient.GetDomainList(request)
	if err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	if err := checkResponse("测试连接", responseRequestID(response), responseError(response)); err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	return true, nil
}

// UploadCertificate 上传或复用京东云 SSL 证书，并通过详情接口回读验收。
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	certificate := providers.CertificateMaterial{Name: name, Domain: domain, CertificatePEM: cert, PrivateKeyPEM: key}
	if err := providers.ValidateCertificateMaterial(certificate, domain, time.Now()); err != nil {
		return providers.NewDeploymentError("京东云上传证书校验失败", false, "", err)
	}
	_, _, err := p.ensureCertificate(context.Background(), certificate)
	return toDeploymentError("上传证书", err)
}

// DiscoverResources 分页读取京东云 CDN 域名并构建生命周期稳定的目标引用。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE}
	}
	if err := p.validateCredentials(); err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED, Error: err}
	}
	resources, err := p.listCDNResources(ctx, deploymentType)
	if err != nil {
		status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		if isPermissionDenied(err) {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED
		}
		return providers.ResourceCatalogResult{Resources: resources, Status: status, Error: err}
	}
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	return providers.ResourceCatalogResult{Resources: resources, Status: status}
}

// ResolveResource 重新读取 CDN 目录并按 targetRef 唯一解析京东云域名。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, providers.NewDeploymentError("京东云 CDN 资源目录不可用", false, requestIDFromError(catalog.Error), catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 确认京东云 CDN 域名仍存在且处于 online 状态。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return providers.NewDeploymentError("京东云 CDN 域名当前不可部署", false, "", err)
	}
	return nil
}

// DeployCertificate 上传或复用证书，绑定精确 CDN 域名并等待配置任务完成后回读。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.DeploymentResult{}, providers.NewDeploymentError("京东云不支持该部署业务", false, "", nil)
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.Domain) == "" || strings.TrimSpace(resource.CreatedAt) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("京东云 CDN 目标缺少 targetRef、域名或创建时间", false, "", nil)
	}
	if err := providers.ValidateCertificateMaterial(certificate, resource.Domain, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("京东云 CDN 证书校验失败", false, "", err)
	}
	preflight, requestID, err := p.getDomainDetail(ctx, resource.Domain)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("读取 CDN 域名", err)
	}
	if err := validateCurrentResource(resource, preflight); err != nil {
		return providers.DeploymentResult{}, err
	}
	certificateID, uploadRequestID, err := p.ensureCertificate(ctx, certificate)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("上传证书", err)
	}
	requestID = firstNonEmpty(uploadRequestID, requestID)
	setRequest := cdnapi.NewSetHttpTypeRequest(resource.Domain)
	setRequest.SetHttpType("https")
	setRequest.SetCertFrom("ssl")
	setRequest.SetSslCertId(certificateID)
	setRequest.SetSyncToSsl(false)
	jumpType := strings.TrimSpace(preflight.JumpType)
	if jumpType == "" {
		jumpType = "default"
	}
	setRequest.SetJumpType(jumpType)
	response, err := p.cdnClient.SetHttpType(setRequest)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("更新 CDN HTTPS 配置", err)
	}
	requestID = firstNonEmpty(responseRequestID(response), requestID)
	if err := checkResponse("更新 CDN HTTPS 配置", responseRequestID(response), responseError(response)); err != nil {
		return providers.DeploymentResult{}, toDeploymentError("更新 CDN HTTPS 配置", err)
	}
	if taskID := strings.TrimSpace(response.Result.TaskId); taskID != "" {
		taskRequestID, waitErr := p.waitTask(ctx, taskID)
		requestID = firstNonEmpty(taskRequestID, requestID)
		if waitErr != nil {
			return providers.DeploymentResult{}, toDeploymentError("等待 CDN 配置任务", waitErr)
		}
	}
	readback, readRequestID, err := p.getDomainDetail(ctx, resource.Domain)
	requestID = firstNonEmpty(readRequestID, requestID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("回读 CDN 域名", err)
	}
	if !strings.EqualFold(strings.TrimSpace(readback.HttpType), "https") || strings.TrimSpace(readback.SslCertId) != certificateID {
		return providers.DeploymentResult{}, providers.NewDeploymentError("京东云 CDN 证书回读尚未生效", true, requestID, nil)
	}
	return providers.DeploymentResult{RequestID: requestID, Message: "京东云 CDN 证书部署成功"}, nil
}

// listCDNResources 分页读取京东云域名，限制最大页数和资源数量。
func (p *Provider) listCDNResources(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, error) {
	if p.cdnClient == nil {
		return nil, providers.NewDeploymentError("京东云 CDN 客户端未初始化", false, "", nil)
	}
	resources := make([]providers.DeploymentResource, 0)
	for page := 1; page <= resourceMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return resources, err
		}
		request := cdnapi.NewGetDomainListRequest()
		request.SetPageNumber(page)
		request.SetPageSize(resourcePageSize)
		response, err := p.cdnClient.GetDomainList(request)
		if err != nil {
			return resources, err
		}
		if err := checkResponse("读取 CDN 域名", responseRequestID(response), responseError(response)); err != nil {
			return resources, err
		}
		for _, item := range response.Result.Domains {
			domain, normalizeErr := providers.NormalizeDomain(item.Domain)
			if normalizeErr != nil {
				continue
			}
			identity, ok := providers.StableDomainIdentity("", domain, item.Created)
			if !ok {
				continue
			}
			status := strings.ToLower(strings.TrimSpace(item.Status))
			availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
			if status != "online" {
				availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
			}
			resources = append(resources, providers.DeploymentResource{
				TargetRef:    providers.BuildTargetRef("jdcloud", deploymentType, identity),
				Label:        domain,
				Domain:       domain,
				Domains:      []string{domain},
				Protocol:     "HTTPS",
				Status:       status,
				Availability: availability,
				ResourceID:   identity,
				CreatedAt:    strings.TrimSpace(item.Created),
			})
			if len(resources) > resourceMaxCount {
				return resources, providers.NewDeploymentError("京东云 CDN 域名数量超过安全上限", false, response.RequestID, nil)
			}
		}
		if len(resources) >= response.Result.TotalCount || len(response.Result.Domains) < resourcePageSize {
			sort.Slice(resources, func(left, right int) bool { return resources[left].Domain < resources[right].Domain })
			return resources, nil
		}
	}
	return resources, providers.NewDeploymentError("京东云 CDN 分页超过安全上限", false, "", nil)
}

// ensureCertificate 按叶证书指纹生成稳定名称，复用或上传证书并回读详情。
func (p *Provider) ensureCertificate(ctx context.Context, certificate providers.CertificateMaterial) (string, string, error) {
	if err := p.validateCredentials(); err != nil {
		return "", "", err
	}
	if p.certificateClient == nil {
		return "", "", providers.NewDeploymentError("京东云 SSL 客户端未初始化", false, "", nil)
	}
	fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	certificateName := "anssl-" + fingerprint[:32]
	existingID, requestID, err := p.findCertificate(ctx, certificateName, certificate.Domain)
	if err != nil {
		return "", requestID, err
	}
	if existingID != "" {
		return existingID, requestID, nil
	}
	if err := ctx.Err(); err != nil {
		return "", requestID, err
	}
	uploadRequest := sslapi.NewUploadCertRequest(certificateName, certificate.PrivateKeyPEM, certificate.CertificatePEM)
	uploadRequest.SetAliasName(certificateName)
	response, err := p.certificateClient.UploadCert(uploadRequest)
	if err != nil {
		return "", requestID, err
	}
	requestID = firstNonEmpty(responseRequestID(response), requestID)
	if err := checkResponse("上传证书", responseRequestID(response), responseError(response)); err != nil {
		return "", requestID, err
	}
	certificateID := strings.TrimSpace(response.Result.CertId)
	if certificateID == "" {
		return "", requestID, providers.NewDeploymentError("京东云上传证书响应缺少 certId", false, requestID, nil)
	}
	detail, detailRequestID, err := p.describeCertificate(ctx, certificateID)
	requestID = firstNonEmpty(detailRequestID, requestID)
	if err != nil {
		return "", requestID, err
	}
	if strings.TrimSpace(detail.CertId) != certificateID || strings.TrimSpace(detail.CertName) != certificateName || !containsDomain(detail.DnsNames, certificate.Domain) {
		return "", requestID, providers.NewDeploymentError("京东云证书回读结果与上传请求不一致", true, requestID, nil)
	}
	return certificateID, requestID, nil
}

// findCertificate 分页查找由同一叶证书指纹派生的证书名称。
func (p *Provider) findCertificate(ctx context.Context, certificateName, domain string) (string, string, error) {
	lastRequestID := ""
	for page := 1; page <= resourceMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return "", lastRequestID, err
		}
		request := sslapi.NewDescribeCertsRequest()
		request.SetPageNumber(page)
		request.SetPageSize(resourcePageSize)
		response, err := p.certificateClient.DescribeCerts(request)
		if err != nil {
			return "", lastRequestID, err
		}
		lastRequestID = firstNonEmpty(responseRequestID(response), lastRequestID)
		if err := checkResponse("读取证书列表", responseRequestID(response), responseError(response)); err != nil {
			return "", lastRequestID, err
		}
		for _, item := range response.Result.CertListDetails {
			if strings.TrimSpace(item.CertName) == certificateName && strings.TrimSpace(item.CertId) != "" && containsDomain(item.DnsNames, domain) {
				return strings.TrimSpace(item.CertId), lastRequestID, nil
			}
		}
		if page*resourcePageSize >= response.Result.TotalCount || len(response.Result.CertListDetails) < resourcePageSize {
			return "", lastRequestID, nil
		}
	}
	return "", lastRequestID, providers.NewDeploymentError("京东云证书分页超过安全上限", false, lastRequestID, nil)
}

// describeCertificate 读取一个京东云 SSL 证书详情并校验业务响应。
func (p *Provider) describeCertificate(ctx context.Context, certificateID string) (sslapi.DescribeCertResult, string, error) {
	if err := ctx.Err(); err != nil {
		return sslapi.DescribeCertResult{}, "", err
	}
	response, err := p.certificateClient.DescribeCert(sslapi.NewDescribeCertRequest(certificateID))
	if err != nil {
		return sslapi.DescribeCertResult{}, "", err
	}
	if err := checkResponse("回读证书", responseRequestID(response), responseError(response)); err != nil {
		return sslapi.DescribeCertResult{}, responseRequestID(response), err
	}
	return response.Result, response.RequestID, nil
}

// getDomainDetail 读取一个京东云 CDN 域名详情并校验业务响应。
func (p *Provider) getDomainDetail(ctx context.Context, domain string) (cdnapi.GetDomainDetailResult, string, error) {
	if err := ctx.Err(); err != nil {
		return cdnapi.GetDomainDetailResult{}, "", err
	}
	response, err := p.cdnClient.GetDomainDetail(cdnapi.NewGetDomainDetailRequest(domain))
	if err != nil {
		return cdnapi.GetDomainDetailResult{}, "", err
	}
	if err := checkResponse("读取 CDN 域名", responseRequestID(response), responseError(response)); err != nil {
		return cdnapi.GetDomainDetailResult{}, responseRequestID(response), err
	}
	return response.Result, response.RequestID, nil
}

// waitTask 等待京东云 CDN 异步配置任务成功，未知状态不会被误判为成功。
func (p *Provider) waitTask(ctx context.Context, taskID string) (string, error) {
	lastRequestID := ""
	for attempt := 0; attempt < taskPollAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(p.pollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return lastRequestID, ctx.Err()
			case <-timer.C:
			}
		}
		response, err := p.cdnClient.QueryDomainConfigStatus(cdnapi.NewQueryDomainConfigStatusRequest(taskID))
		if err != nil {
			return lastRequestID, err
		}
		lastRequestID = firstNonEmpty(responseRequestID(response), lastRequestID)
		if err := checkResponse("查询 CDN 配置任务", responseRequestID(response), responseError(response)); err != nil {
			return lastRequestID, err
		}
		switch strings.ToLower(strings.TrimSpace(response.Result.TaskStatus)) {
		case "success", "succeeded", "finished":
			return lastRequestID, nil
		case "fail", "failed", "error":
			return lastRequestID, providers.NewDeploymentError("京东云 CDN 配置任务失败", false, lastRequestID, nil)
		case "running", "pending", "processing", "wait", "":
			continue
		default:
			return lastRequestID, providers.NewDeploymentError("京东云 CDN 配置任务返回未知状态", true, lastRequestID, nil)
		}
	}
	return lastRequestID, providers.NewDeploymentError("京东云 CDN 配置任务等待超时", true, lastRequestID, nil)
}

// validateCurrentResource 防止同名 CDN 域名删除重建后沿用旧 targetRef。
func validateCurrentResource(resource providers.DeploymentResource, detail cdnapi.GetDomainDetailResult) error {
	domain, err := providers.NormalizeDomain(detail.Domain)
	if err != nil || domain != resource.Domain || strings.TrimSpace(detail.Created) != strings.TrimSpace(resource.CreatedAt) {
		return providers.NewDeploymentError("京东云 CDN 域名身份已变化，请重新关联资源", false, "", err)
	}
	if !strings.EqualFold(strings.TrimSpace(detail.Status), "online") {
		return providers.NewDeploymentError("京东云 CDN 域名当前不可部署", false, "", nil)
	}
	return nil
}

// containsDomain 判断云端域名集合是否包含规范化目标域名。
func containsDomain(domains []string, target string) bool {
	normalizedTarget, err := providers.NormalizeDomain(target)
	if err != nil {
		return false
	}
	for _, rawDomain := range domains {
		domain, normalizeErr := providers.NormalizeDomain(rawDomain)
		if normalizeErr == nil && domain == normalizedTarget {
			return true
		}
	}
	return false
}

// checkResponse 将京东云响应体内的业务错误转换成带请求 ID 的错误。
func checkResponse(operation, requestID string, responseError core.ErrorResponse) error {
	if responseError.Code == 0 {
		return nil
	}
	retryable := responseError.Code == 429 || responseError.Code >= 500
	return &apiError{Operation: operation, Code: responseError.Code, Status: responseError.Status, RequestID: requestID, Retryable: retryable}
}

// responseCarrier 是京东云所有响应共享的只读元数据视图。
type responseCarrier interface{}

// responseRequestID 从已知京东云 SDK 响应中提取请求 ID。
func responseRequestID(response responseCarrier) string {
	switch typed := response.(type) {
	case *cdnapi.GetDomainListResponse:
		return strings.TrimSpace(typed.RequestID)
	case *cdnapi.GetDomainDetailResponse:
		return strings.TrimSpace(typed.RequestID)
	case *cdnapi.SetHttpTypeResponse:
		return strings.TrimSpace(typed.RequestID)
	case *cdnapi.QueryDomainConfigStatusResponse:
		return strings.TrimSpace(typed.RequestID)
	case *sslapi.UploadCertResponse:
		return strings.TrimSpace(typed.RequestID)
	case *sslapi.DescribeCertResponse:
		return strings.TrimSpace(typed.RequestID)
	case *sslapi.DescribeCertsResponse:
		return strings.TrimSpace(typed.RequestID)
	default:
		return ""
	}
}

// responseError 从已知京东云 SDK 响应中提取业务错误字段。
func responseError(response responseCarrier) core.ErrorResponse {
	switch typed := response.(type) {
	case *cdnapi.GetDomainListResponse:
		return typed.Error
	case *cdnapi.GetDomainDetailResponse:
		return typed.Error
	case *cdnapi.SetHttpTypeResponse:
		return typed.Error
	case *cdnapi.QueryDomainConfigStatusResponse:
		return typed.Error
	case *sslapi.UploadCertResponse:
		return typed.Error
	case *sslapi.DescribeCertResponse:
		return typed.Error
	case *sslapi.DescribeCertsResponse:
		return typed.Error
	default:
		return core.ErrorResponse{Code: 500, Status: "InvalidResponse"}
	}
}

// validateCredentials 拒绝空凭据和控制字符。
func (p *Provider) validateCredentials() error {
	if p == nil || strings.TrimSpace(p.accessKey) == "" || strings.TrimSpace(p.secretKey) == "" {
		return providers.NewDeploymentError("京东云 accessKeyId 或 accessKeySecret 未配置", false, "", nil)
	}
	if strings.ContainsAny(p.accessKey+p.secretKey, "\r\n\x00") {
		return providers.NewDeploymentError("京东云访问密钥格式无效", false, "", nil)
	}
	return nil
}

// isPermissionDenied 判断京东云业务错误是否属于认证或授权不足。
func isPermissionDenied(err error) bool {
	var requestError *apiError
	if !errors.As(err, &requestError) {
		return false
	}
	status := strings.ToLower(strings.TrimSpace(requestError.Status))
	return requestError.Code == 401 || requestError.Code == 403 || strings.Contains(status, "unauthorized") || strings.Contains(status, "forbidden")
}

// requestIDFromError 从京东云业务错误中提取请求 ID。
func requestIDFromError(err error) string {
	var requestError *apiError
	if errors.As(err, &requestError) {
		return strings.TrimSpace(requestError.RequestID)
	}
	return ""
}

// toDeploymentError 将京东云 SDK 和业务错误转换为统一部署错误。
func toDeploymentError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}
	var requestError *apiError
	if errors.As(err, &requestError) {
		return providers.NewDeploymentError("京东云"+operation+"失败", requestError.Retryable, requestError.RequestID, err)
	}
	return providers.NewDeploymentError("京东云"+operation+"失败", false, "", err)
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
