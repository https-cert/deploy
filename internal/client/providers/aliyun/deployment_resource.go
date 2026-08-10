package aliyun

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/darabonba-openapi/v2/models"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

const (
	aliyunCDNEndpoint  = "cdn.aliyuncs.com"
	aliyunDCDNEndpoint = "dcdn.aliyuncs.com"
	aliyunESAEndpoint  = "esa.cn-hangzhou.aliyuncs.com"
	aliyunSLBEndpoint  = "slb.aliyuncs.com"

	aliyunCDNVersion  = "2018-05-10"
	aliyunDCDNVersion = "2018-01-15"
	aliyunESAVersion  = "2024-09-10"
	aliyunSLBVersion  = "2014-05-15"
)

// deploymentAPI 是 CDN、DCDN、ESA 和 CLB 资源部署共用的最小 OpenAPI 调用接口。
// 通过接口隔离 SDK，可以在单元测试中验证精确资源路由而不访问云端。
type deploymentAPI interface {
	// Call 发起一次带 context 的阿里云控制面请求。
	Call(ctx context.Context, request cloudAPIRequest) (cloudAPIResponse, error)
}

// cloudAPIRequest 描述一次不包含凭据的阿里云 RPC 调用。
type cloudAPIRequest struct {
	// Endpoint 是目标产品的 API 域名。
	Endpoint string
	// Action 是阿里云 API action 名称。
	Action string
	// Version 是产品 API 版本。
	Version string
	// Method 是 HTTP 请求方法。
	Method string
	// Query 是 RPC 查询参数，不得用于日志输出。
	Query map[string]string
	// Body 是 RPC 表单主体，不得用于日志输出。
	Body map[string]string
}

// cloudAPIResponse 保存控制面响应的脱敏元数据和业务正文。
type cloudAPIResponse struct {
	// Body 是已标准化为 map 的业务响应正文。
	Body map[string]any
	// RequestID 是阿里云请求编号，可安全回传用于排障。
	RequestID string
}

// openAPIDeploymentAPI 使用 Darabonba OpenAPI 客户端执行资源部署请求。
type openAPIDeploymentAPI struct {
	// clients 以 endpoint 为键保存已初始化的 OpenAPI 客户端。
	clients map[string]*openapi.Client
}

// cloudAPIError 保存可用于重试判断的阿里云 API 错误元数据。
type cloudAPIError struct {
	// StatusCode 是云端返回的 HTTP 状态码，未知时为零。
	StatusCode int
	// Code 是云端错误码，不包含请求参数。
	Code string
	// RequestID 是云端请求编号。
	RequestID string
	// Message 是已经脱敏的错误说明。
	Message string
	// Cause 保存底层网络或 SDK 错误，日志应输出 Error() 而不是该字段。
	Cause error
}

// Error 返回不会泄露资源定位信息的错误说明。
func (e *cloudAPIError) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	return "阿里云控制面请求失败"
}

// Unwrap 返回底层错误，供 errors.Is 和 errors.As 继续判断网络故障。
func (e *cloudAPIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// GetStatusCode 返回云端 HTTP 状态码，供统一错误分类使用。
func (e *cloudAPIError) GetStatusCode() *int {
	if e == nil || e.StatusCode == 0 {
		return nil
	}
	statusCode := e.StatusCode
	return &statusCode
}

// GetCode 返回云端错误码，供统一错误分类使用。
func (e *cloudAPIError) GetCode() *string {
	if e == nil || strings.TrimSpace(e.Code) == "" {
		return nil
	}
	code := e.Code
	return &code
}

// GetRequestId 返回云端请求编号，供统一错误分类使用。
func (e *cloudAPIError) GetRequestId() *string {
	if e == nil || strings.TrimSpace(e.RequestID) == "" {
		return nil
	}
	requestID := e.RequestID
	return &requestID
}

// newOpenAPIDeploymentAPI 为阿里云资源部署产品构建独立的 OpenAPI 客户端。
func newOpenAPIDeploymentAPI(accessKeyID, accessKeySecret string) (deploymentAPI, error) {
	endpoints := []string{aliyunCDNEndpoint, aliyunDCDNEndpoint, aliyunESAEndpoint, aliyunSLBEndpoint}
	clients := make(map[string]*openapi.Client, len(endpoints))
	for _, endpoint := range endpoints {
		client, err := buildOpenAPIClient(accessKeyID, accessKeySecret, endpoint)
		if err != nil {
			return nil, err
		}
		clients[endpoint] = client
	}
	return &openAPIDeploymentAPI{clients: clients}, nil
}

// Call 使用调用方 context 触发一个精确的阿里云 RPC action。
func (a *openAPIDeploymentAPI) Call(ctx context.Context, request cloudAPIRequest) (cloudAPIResponse, error) {
	if a == nil {
		return cloudAPIResponse{}, &cloudAPIError{Message: "阿里云控制面客户端未初始化"}
	}
	client := a.clients[strings.TrimSpace(request.Endpoint)]
	if client == nil {
		return cloudAPIResponse{}, &cloudAPIError{Message: "阿里云产品客户端未初始化"}
	}
	if strings.TrimSpace(request.Action) == "" || strings.TrimSpace(request.Version) == "" {
		return cloudAPIResponse{}, &cloudAPIError{Message: "阿里云控制面请求参数不完整"}
	}

	openAPIRequest := &models.OpenApiRequest{Query: stringPointers(request.Query)}
	if len(request.Body) > 0 {
		body := make(map[string]any, len(request.Body))
		for key, value := range request.Body {
			body[key] = value
		}
		openAPIRequest.Body = body
	}

	params := getParams(request.Action, request.Version, request.Method)
	if len(request.Body) > 0 {
		requestBodyType := "formData"
		params.ReqBodyType = &requestBodyType
	}
	response, err := callOpenAPIWithContext(ctx, client, params, openAPIRequest)
	if err != nil {
		return cloudAPIResponse{}, err
	}
	normalized, ok := normalizeToMap(response)
	if !ok {
		return cloudAPIResponse{}, &cloudAPIError{Message: "阿里云控制面响应格式异常"}
	}
	body := normalized
	if responseBody, found := getMapValue(normalized, "body"); found {
		if parsedBody, parsed := normalizeToMap(responseBody); parsed {
			body = parsedBody
		}
	}
	return cloudAPIResponse{
		Body:      body,
		RequestID: responseRequestID(normalized),
	}, nil
}

// callOpenAPIWithContext 在 SDK 不直接接收 context 的情况下，将 deadline 映射为运行时超时并优先返回取消信号。
func callOpenAPIWithContext(ctx context.Context, client *openapi.Client, params *models.Params, request *models.OpenApiRequest) (map[string]any, error) {
	if client == nil {
		return nil, &cloudAPIError{Message: "阿里云控制面客户端未初始化"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	runtime := &util.RuntimeOptions{}
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		milliseconds := int(remaining / time.Millisecond)
		if milliseconds < 1 {
			milliseconds = 1
		}
		runtime.ReadTimeout = &milliseconds
		runtime.ConnectTimeout = &milliseconds
	}

	type result struct {
		// response 是 SDK 返回的原始响应。
		response map[string]any
		// err 是 SDK 调用错误。
		err error
	}
	done := make(chan result, 1)
	go func() {
		response, err := client.CallApi(params, request, runtime)
		done <- result{response: response, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case callResult := <-done:
		if callResult.err != nil {
			return nil, callResult.err
		}
		return callResult.response, nil
	}
}

// stringPointers 将字符串 map 转为 Darabonba 需要的指针 map。
func stringPointers(values map[string]string) map[string]*string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]*string, len(values))
	for key, value := range values {
		valueCopy := value
		result[key] = &valueCopy
	}
	return result
}

// DeployCertificate 将证书部署到一个明确阿里云业务下精确解析出的资源。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, business deployPB.ExecuteBusinesType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("资源部署", err)
	}
	if err := validateAliyunDeploymentResource(business, resource); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云部署资源配置无效", false, "", newSafeAliyunCause("资源校验", err))
	}
	if err := providers.ValidateCertificateMaterial(certificate, resource.Domain, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云部署资源证书校验失败", false, "", newSafeAliyunCause("证书校验", err))
	}

	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN:
		return p.deployCDN(ctx, certificate, resource)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN:
		return p.deployDCDN(ctx, certificate, resource)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA:
		return p.deployESA(ctx, certificate, resource)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN:
		return p.deployOSS(ctx, certificate, resource)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
		return p.deployCLB(ctx, certificate, resource)
	default:
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云不支持该部署业务", false, "", nil)
	}
}

// validateAliyunDeploymentResource 拒绝缺少引用和产品专属定位字段的直接调用。
func validateAliyunDeploymentResource(business deployPB.ExecuteBusinesType, resource providers.DeploymentResource) error {
	if strings.TrimSpace(resource.TargetRef) == "" {
		return fmt.Errorf("targetRef 不能为空")
	}
	if strings.TrimSpace(resource.Domain) == "" {
		return fmt.Errorf("目标域名不能为空")
	}

	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN, deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN:
		return nil
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA:
		if _, err := parseESASiteID(resource.SiteID); err != nil {
			return err
		}
		return nil
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN:
		if strings.TrimSpace(resource.Region) == "" || strings.TrimSpace(resource.Bucket) == "" {
			return fmt.Errorf("OSS 目标缺少地域或 Bucket")
		}
		return nil
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
		if strings.TrimSpace(resource.Region) == "" || strings.TrimSpace(resource.LoadBalancerID) == "" {
			return fmt.Errorf("CLB 目标缺少地域或负载均衡实例")
		}
		if resource.ListenerPort < 1 || resource.ListenerPort > 65535 {
			return fmt.Errorf("CLB 监听端口无效")
		}
		return nil
	default:
		return fmt.Errorf("不支持的阿里云部署业务")
	}
}

// parseESASiteID 校验 ESA Site ID 为正整数，但不在错误中回显其值。
func parseESASiteID(rawSiteID string) (string, error) {
	siteID := strings.TrimSpace(rawSiteID)
	if siteID == "" {
		return "", fmt.Errorf("ESA 目标缺少 SiteId")
	}
	parsed, err := strconv.ParseInt(siteID, 10, 64)
	if err != nil || parsed <= 0 {
		return "", fmt.Errorf("ESA SiteId 格式无效")
	}
	return siteID, nil
}

// acceleratedProduct 描述一种需要先校验 HTTPS 的阿里云加速域名产品。
type acceleratedProduct struct {
	// DisplayName 是用于安全结果说明的产品名称。
	DisplayName string
	// Endpoint 是对应产品的 OpenAPI endpoint。
	Endpoint string
	// Version 是对应产品的 API 版本。
	Version string
	// PreflightAction 是读取精确域名配置的 action。
	PreflightAction string
	// WriteAction 是写入上传证书的 action。
	WriteAction string
	// ReadbackAction 是回读域名证书信息的 action。
	ReadbackAction string
	// DetailKey 是前置响应中域名详情对象的键。
	DetailKey string
	// HTTPSKey 是详情对象中 HTTPS 是否启用的键。
	HTTPSKey string
}

// deployCDN 部署证书到一个已配置的阿里云 CDN 精确域名。
func (p *Provider) deployCDN(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	return p.deployAcceleratedDomain(ctx, certificate, target, acceleratedProduct{
		DisplayName:     "CDN",
		Endpoint:        aliyunCDNEndpoint,
		Version:         aliyunCDNVersion,
		PreflightAction: "DescribeCdnDomainDetail",
		WriteAction:     "SetCdnDomainSSLCertificate",
		ReadbackAction:  "DescribeDomainCertificateInfo",
		DetailKey:       "GetDomainDetailModel",
		HTTPSKey:        "ServerCertificateStatus",
	})
}

// deployDCDN 部署证书到一个已配置的阿里云 DCDN 精确域名。
func (p *Provider) deployDCDN(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	return p.deployAcceleratedDomain(ctx, certificate, target, acceleratedProduct{
		DisplayName:     "DCDN",
		Endpoint:        aliyunDCDNEndpoint,
		Version:         aliyunDCDNVersion,
		PreflightAction: "DescribeDcdnDomainDetail",
		WriteAction:     "SetDcdnDomainSSLCertificate",
		ReadbackAction:  "DescribeDcdnDomainCertificateInfo",
		DetailKey:       "DomainDetail",
		HTTPSKey:        "SSLProtocol",
	})
}

// deployAcceleratedDomain 执行加速域名的精确预检、写入和控制面回读。
func (p *Provider) deployAcceleratedDomain(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource, product acceleratedProduct) (providers.DeploymentResult, error) {
	if p == nil || p.deploymentAPI == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云部署客户端未初始化", false, "", nil)
	}

	preflight, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: product.Endpoint,
		Action:   product.PreflightAction,
		Version:  product.Version,
		Method:   "POST",
		Query: map[string]string{
			"DomainName": target.Domain,
		},
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取"+product.DisplayName+"域名配置", err)
	}
	if err := validateAcceleratedDomain(preflight.Body, target.Domain, product); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云"+product.DisplayName+"目标校验失败", false, preflight.RequestID, newSafeAliyunCause("目标校验", err))
	}

	certificateName := deploymentCertificateName(certificate)
	written, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: product.Endpoint,
		Action:   product.WriteAction,
		Version:  product.Version,
		Method:   "POST",
		Query: map[string]string{
			"CertName":    certificateName,
			"CertType":    "upload",
			"DomainName":  target.Domain,
			"SSLPri":      certificate.PrivateKeyPEM,
			"SSLProtocol": "on",
			"SSLPub":      certificate.CertificatePEM,
		},
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("更新"+product.DisplayName+"域名证书", err)
	}

	readback, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: product.Endpoint,
		Action:   product.ReadbackAction,
		Version:  product.Version,
		Method:   "POST",
		Query: map[string]string{
			"DomainName": target.Domain,
		},
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("回读"+product.DisplayName+"域名证书", written.RequestID, err)
	}
	if matched, applying := acceleratedCertificateReadback(readback.Body, certificateName); !matched && !applying {
		requestID := firstNonEmpty(written.RequestID, readback.RequestID)
		return providers.DeploymentResult{}, providers.NewDeploymentError(
			"阿里云"+product.DisplayName+"控制面尚未确认新证书",
			true,
			requestID,
			newSafeAliyunCause("控制面回读", fmt.Errorf("未找到提交的证书配置")),
		)
	}

	return providers.DeploymentResult{
		RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
		Message:   "阿里云" + product.DisplayName + "域名证书部署成功",
	}, nil
}

// validateAcceleratedDomain 确认读取到的就是目标域名，且该域名当前启用了 HTTPS。
func validateAcceleratedDomain(body map[string]any, targetDomain string, product acceleratedProduct) error {
	detailValue, found := getMapValue(body, product.DetailKey)
	if !found {
		return fmt.Errorf("响应缺少域名详情")
	}
	detail, ok := normalizeToMap(detailValue)
	if !ok {
		return fmt.Errorf("域名详情格式异常")
	}
	returnedDomain := strings.TrimSpace(mapString(detail, "DomainName"))
	if returnedDomain == "" || !strings.EqualFold(returnedDomain, strings.TrimSpace(targetDomain)) {
		return fmt.Errorf("云端返回的域名与目标不一致")
	}
	if !strings.EqualFold(strings.TrimSpace(mapString(detail, product.HTTPSKey)), "on") {
		return fmt.Errorf("目标域名未启用 HTTPS")
	}
	return nil
}

// acceleratedCertificateReadback 判断证书详情是否已经显示本次提交的证书名称或处于控制面应用中。
func acceleratedCertificateReadback(body map[string]any, certificateName string) (matched bool, applying bool) {
	certInfosValue, found := getMapValue(body, "CertInfos")
	if !found {
		return false, responseHasApplyingStatus(body)
	}
	certInfos, ok := normalizeToMap(certInfosValue)
	if !ok {
		return false, responseHasApplyingStatus(body)
	}
	for _, record := range mapSlice(certInfos, "CertInfo") {
		if strings.EqualFold(strings.TrimSpace(mapString(record, "CertName")), strings.TrimSpace(certificateName)) {
			return true, false
		}
		if isApplyingStatus(mapString(record, "Status"), mapString(record, "CertStatus")) {
			applying = true
		}
	}
	return false, applying || responseHasApplyingStatus(body)
}

// deployESA 部署证书到一个 Site 中精确匹配的 ESA Record。
func (p *Provider) deployESA(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	if p == nil || p.deploymentAPI == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云部署客户端未初始化", false, "", nil)
	}
	siteID, err := parseESASiteID(target.SiteID)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ESA 目标配置无效", false, "", newSafeAliyunCause("目标校验", err))
	}

	preflight, err := p.listESACertificatesByRecord(ctx, siteID, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取 ESA Record 证书配置", err)
	}
	preflightRecord, found := findESARecord(preflight.Body, target.Domain)
	if !found {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ESA 目标校验失败", false, preflight.RequestID, newSafeAliyunCause("目标校验", fmt.Errorf("未找到精确 Record")))
	}

	fingerprint, _, fingerprintErr := extractCertFingerprintAndSerial(certificate.CertificatePEM)
	if fingerprintErr != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ESA 证书校验失败", false, preflight.RequestID, newSafeAliyunCause("证书指纹", fingerprintErr))
	}
	if strings.EqualFold(strings.TrimSpace(mapString(preflightRecord, "Status")), "configured") && esaRecordContainsFingerprint(preflightRecord, fingerprint) {
		return providers.DeploymentResult{
			RequestID: preflight.RequestID,
			Message:   "阿里云 ESA Record 已配置当前证书",
		}, nil
	}

	written, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunESAEndpoint,
		Action:   "SetCertificate",
		Version:  aliyunESAVersion,
		Method:   "POST",
		Body: map[string]string{
			"Certificate": certificate.CertificatePEM,
			"Name":        deploymentCertificateName(certificate),
			"PrivateKey":  certificate.PrivateKeyPEM,
			"SiteId":      siteID,
			"Type":        "upload",
		},
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("更新 ESA 证书", err)
	}

	readback, err := p.listESACertificatesByRecord(ctx, siteID, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("回读 ESA Record 证书配置", written.RequestID, err)
	}
	readbackRecord, found := findESARecord(readback.Body, target.Domain)
	if !found {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ESA 控制面未返回目标 Record", true, firstNonEmpty(written.RequestID, readback.RequestID), nil)
	}
	status := strings.ToLower(strings.TrimSpace(mapString(readbackRecord, "Status")))
	if esaRecordContainsFingerprint(readbackRecord, fingerprint) && (status == "configured" || isApplyingStatus(status)) {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
			Message:   "阿里云 ESA Record 证书部署成功",
		}, nil
	}
	if isApplyingStatus(status) {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
			Message:   "阿里云 ESA Record 证书已提交，控制面正在应用",
		}, nil
	}
	return providers.DeploymentResult{}, providers.NewDeploymentError(
		"阿里云 ESA 控制面尚未确认新证书",
		true,
		firstNonEmpty(written.RequestID, readback.RequestID),
		newSafeAliyunCause("控制面回读", fmt.Errorf("Record 指纹或状态未确认")),
	)
}

// listESACertificatesByRecord 只查询指定 Site 和精确 Record，不扫描其他站点或记录。
func (p *Provider) listESACertificatesByRecord(ctx context.Context, siteID, recordName string) (cloudAPIResponse, error) {
	if p == nil || p.deploymentAPI == nil {
		return cloudAPIResponse{}, &cloudAPIError{Message: "阿里云 ESA 客户端未初始化"}
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunESAEndpoint,
		Action:   "ListCertificatesByRecord",
		Version:  aliyunESAVersion,
		Method:   "POST",
		Query: map[string]string{
			"Detail":     "true",
			"RecordName": recordName,
			"SiteId":     siteID,
			"ValidOnly":  "false",
		},
	})
}

// findESARecord 从 ListCertificatesByRecord 响应中找出唯一的精确 Record。
func findESARecord(body map[string]any, targetDomain string) (map[string]any, bool) {
	var matched map[string]any
	for _, record := range mapSlice(body, "Result") {
		if !strings.EqualFold(strings.TrimSpace(mapString(record, "RecordName")), strings.TrimSpace(targetDomain)) {
			continue
		}
		if matched != nil {
			return nil, false
		}
		matched = record
	}
	return matched, matched != nil
}

// esaRecordContainsFingerprint 判断 ESA Record 中是否包含当前 PEM 的 SHA-256 指纹。
func esaRecordContainsFingerprint(record map[string]any, fingerprint string) bool {
	targetFingerprint := normalizeComparableToken(fingerprint)
	if targetFingerprint == "" {
		return false
	}
	for _, certificate := range mapSlice(record, "Certificates") {
		for _, key := range []string{"FingerprintSha256", "Fingerprint", "CertFingerprint"} {
			value := normalizeComparableToken(mapString(certificate, key))
			if value != "" && value == targetFingerprint {
				return true
			}
		}
	}
	return false
}

// deploymentCertificateName 生成稳定、无资源标识的上传证书名称，用于 CDN/DCDN 的回读匹配。
func deploymentCertificateName(certificate providers.CertificateMaterial) string {
	sum := sha256.Sum256([]byte(certificate.CertificatePEM))
	return fmt.Sprintf("anssl-%x", sum[:8])
}

// mapString 从大小写不敏感的 map 中读取一个可转换为字符串的字段。
func mapString(data map[string]any, key string) string {
	value, found := getMapValue(data, key)
	if !found {
		return ""
	}
	return strings.TrimSpace(anyToString(value))
}

// getMapValue 以大小写不敏感的方式读取 map 字段。
func getMapValue(data map[string]any, key string) (any, bool) {
	for actualKey, value := range data {
		if strings.EqualFold(actualKey, key) {
			return value, true
		}
	}
	return nil, false
}

// mapSlice 将一个 map 字段归一化为 map 列表，兼容单项与数组两种响应形态。
func mapSlice(data map[string]any, key string) []map[string]any {
	value, found := getMapValue(data, key)
	if !found {
		return nil
	}
	normalized := normalizeValue(value)
	switch typedValue := normalized.(type) {
	case []any:
		result := make([]map[string]any, 0, len(typedValue))
		for _, item := range typedValue {
			if itemMap, ok := normalizeToMap(item); ok {
				result = append(result, itemMap)
			}
		}
		return result
	case map[string]any:
		return []map[string]any{typedValue}
	default:
		return nil
	}
}

// responseRequestID 从 OpenAPI 原始响应中提取请求编号。
func responseRequestID(data map[string]any) string {
	for _, key := range []string{"RequestId", "RequestID", "requestId", "requestID"} {
		if value, found := getMapValue(data, key); found {
			if requestID := strings.TrimSpace(anyToString(value)); requestID != "" {
				return requestID
			}
		}
	}
	if body, found := getMapValue(data, "body"); found {
		if bodyMap, ok := normalizeToMap(body); ok {
			return responseRequestID(bodyMap)
		}
	}
	return ""
}

// responseHasApplyingStatus 递归判断响应中是否已进入可接受的应用状态。
func responseHasApplyingStatus(value any) bool {
	normalized := normalizeValue(value)
	switch typedValue := normalized.(type) {
	case map[string]any:
		for key, child := range typedValue {
			if strings.EqualFold(key, "Status") && isApplyingStatus(anyToString(child)) {
				return true
			}
			if responseHasApplyingStatus(child) {
				return true
			}
		}
	case []any:
		for _, child := range typedValue {
			if responseHasApplyingStatus(child) {
				return true
			}
		}
	}
	return false
}

// isApplyingStatus 判断控制面状态是否表示写入已接受但仍在异步应用。
func isApplyingStatus(values ...string) bool {
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "applying", "processing", "configuring":
			return true
		}
	}
	return false
}

// firstNonEmpty 返回第一个非空字符串，用于优先保留写操作请求编号。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// safeAliyunCause 将底层错误包裹为安全的日志文本，同时保留 errors.Is/errors.As 链路。
type safeAliyunCause struct {
	// Operation 是不含资源定位信息的本地操作名称。
	Operation string
	// Cause 是底层错误，仅用于错误链判断。
	Cause error
}

// Error 返回不会回显证书、私钥、Bucket、Site ID 或 endpoint 的错误文本。
func (e *safeAliyunCause) Error() string {
	if e == nil || strings.TrimSpace(e.Operation) == "" {
		return "阿里云资源操作失败"
	}
	return "阿里云" + e.Operation + "失败"
}

// Unwrap 保留原始错误链，方便上层识别 context 和网络错误。
func (e *safeAliyunCause) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// newSafeAliyunCause 构建可安全记录的底层错误包装。
func newSafeAliyunCause(operation string, cause error) error {
	return &safeAliyunCause{Operation: operation, Cause: cause}
}

// newAliyunDeploymentError 根据 SDK、HTTP 和网络错误生成统一的云部署错误。
func newAliyunDeploymentError(operation string, err error) error {
	return newAliyunDeploymentErrorWithRequestID(operation, "", err)
}

// newAliyunDeploymentErrorWithRequestID 在已有写请求编号时保留该编号，避免回读错误覆盖它。
func newAliyunDeploymentErrorWithRequestID(operation, fallbackRequestID string, err error) error {
	retryable, requestID := classifyAliyunError(err)
	return providers.NewDeploymentError(
		"阿里云"+operation+"失败",
		retryable,
		firstNonEmpty(fallbackRequestID, requestID),
		newSafeAliyunCause(operation, err),
	)
}

// classifyAliyunError 识别可重试的网络、超时、限流和服务端临时错误。
func classifyAliyunError(err error) (retryable bool, requestID string) {
	if err == nil {
		return false, ""
	}
	if errors.Is(err, context.Canceled) {
		return false, ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true, ""
	}

	statusCode, code, requestID := aliyunErrorMetadata(err)
	if statusCode == 429 || statusCode >= 500 {
		return true, requestID
	}
	lowerCode := strings.ToLower(code)
	for _, token := range []string{"throttl", "limit", "timeout", "internal", "serviceunavailable", "systembusy", "temporar"} {
		if strings.Contains(lowerCode, token) {
			return true, requestID
		}
	}

	var networkError net.Error
	if errors.As(err, &networkError) {
		return true, requestID
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return true, requestID
	}
	return false, requestID
}

// aliyunErrorMetadata 从 SDK 或本地适配器错误中读取状态码、错误码和请求编号。
func aliyunErrorMetadata(err error) (statusCode int, code, requestID string) {
	var statusCodeError interface{ GetStatusCode() *int }
	if errors.As(err, &statusCodeError) && statusCodeError.GetStatusCode() != nil {
		statusCode = *statusCodeError.GetStatusCode()
	}
	var codeError interface{ GetCode() *string }
	if errors.As(err, &codeError) && codeError.GetCode() != nil {
		code = strings.TrimSpace(*codeError.GetCode())
	}
	var requestIDError interface{ GetRequestId() *string }
	if errors.As(err, &requestIDError) && requestIDError.GetRequestId() != nil {
		requestID = strings.TrimSpace(*requestIDError.GetRequestId())
	}
	reflectedStatusCode, reflectedCode, reflectedData := reflectedSDKErrorMetadata(err)
	if statusCode == 0 {
		statusCode = reflectedStatusCode
	}
	if code == "" {
		code = reflectedCode
	}
	if requestID == "" {
		requestID = requestIDFromSDKData(reflectedData)
	}
	return statusCode, code, requestID
}

// reflectedSDKErrorMetadata 读取 Darabonba SDKError 的导出字段，避免额外绑定 tea 的具体版本。
func reflectedSDKErrorMetadata(err error) (statusCode int, code, data string) {
	for current := err; current != nil; current = errors.Unwrap(current) {
		value := reflect.ValueOf(current)
		for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
			if value.IsNil() {
				break
			}
			value = value.Elem()
		}
		if !value.IsValid() || value.Kind() != reflect.Struct {
			continue
		}
		if statusCode == 0 {
			if field := value.FieldByName("StatusCode"); field.IsValid() && field.CanInterface() {
				if parsed, ok := anyToInt64(normalizeValue(field.Interface())); ok {
					statusCode = int(parsed)
				}
			}
		}
		if code == "" {
			if field := value.FieldByName("Code"); field.IsValid() && field.CanInterface() {
				code = strings.TrimSpace(anyToString(normalizeValue(field.Interface())))
			}
		}
		if data == "" {
			if field := value.FieldByName("Data"); field.IsValid() && field.CanInterface() {
				data = reflectedRawString(field)
			}
		}
	}
	return statusCode, code, data
}

// reflectedRawString 解引用 SDK 字段但保留 JSON 字符串原文，避免提前解析后无法提取 request ID。
func reflectedRawString(value reflect.Value) string {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return ""
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return ""
	}
	if value.Kind() == reflect.String {
		return strings.TrimSpace(value.String())
	}
	if value.CanInterface() {
		return strings.TrimSpace(anyToString(normalizeValue(value.Interface())))
	}
	return ""
}

// requestIDFromSDKData 只从 SDK 的 JSON Data 中读取请求编号，不传播其他响应字段。
func requestIDFromSDKData(rawData string) string {
	var data map[string]any
	if err := json.Unmarshal([]byte(rawData), &data); err != nil {
		return ""
	}
	return firstNonEmpty(mapString(data, "RequestId"), mapString(data, "requestId"))
}
