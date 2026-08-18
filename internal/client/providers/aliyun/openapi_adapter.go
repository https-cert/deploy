package aliyun

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/darabonba-openapi/v2/models"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
)

const (
	aliyunCDNEndpoint  = "cdn.aliyuncs.com"
	aliyunDCDNEndpoint = "dcdn.aliyuncs.com"
	aliyunESAEndpoint  = "esa.cn-hangzhou.aliyuncs.com"
	aliyunSLBEndpoint  = "slb.aliyuncs.com"
	aliyunCASEndpoint  = "cas.aliyuncs.com"
	aliyunECSEndpoint  = "ecs.aliyuncs.com"

	aliyunCDNVersion  = "2018-05-10"
	aliyunDCDNVersion = "2018-01-15"
	aliyunESAVersion  = "2024-09-10"
	aliyunSLBVersion  = "2014-05-15"
	aliyunCASVersion  = "2020-04-07"
	aliyunECSVersion  = "2014-05-26"
	aliyunALBVersion  = "2020-06-16"
	aliyunNLBVersion  = "2022-04-30"

	aliyunAPICallTimeout = 30 * time.Second
)

// deploymentAPI 是阿里云各产品资源部署共用的最小 OpenAPI 调用接口。
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
	// accessKeyID 是创建地域产品客户端所需的访问密钥标识，不得写入日志。
	accessKeyID string
	// accessKeySecret 是创建地域产品客户端所需的访问密钥密钥，不得写入日志。
	accessKeySecret string
	// clientsMu 保护地域客户端的延迟创建和读取。
	clientsMu sync.RWMutex
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
	endpoints := []string{
		aliyunCDNEndpoint,
		aliyunDCDNEndpoint,
		aliyunESAEndpoint,
		aliyunSLBEndpoint,
		aliyunCASEndpoint,
		aliyunECSEndpoint,
	}
	clients := make(map[string]*openapi.Client, len(endpoints))
	for _, endpoint := range endpoints {
		client, err := buildOpenAPIClient(accessKeyID, accessKeySecret, endpoint)
		if err != nil {
			return nil, err
		}
		clients[endpoint] = client
	}
	return &openAPIDeploymentAPI{
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
		clients:         clients,
	}, nil
}

// Call 使用调用方 context 触发一个精确的阿里云 RPC action。
func (a *openAPIDeploymentAPI) Call(ctx context.Context, request cloudAPIRequest) (cloudAPIResponse, error) {
	if a == nil {
		return cloudAPIResponse{}, &cloudAPIError{Message: "阿里云控制面客户端未初始化"}
	}
	client, err := a.clientForEndpoint(request.Endpoint)
	if err != nil {
		return cloudAPIResponse{}, err
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

// clientForEndpoint 返回静态产品客户端，或按白名单地域域名延迟创建 ALB/NLB 客户端。
func (a *openAPIDeploymentAPI) clientForEndpoint(rawEndpoint string) (*openapi.Client, error) {
	endpoint := strings.ToLower(strings.TrimSpace(rawEndpoint))
	if endpoint == "" {
		return nil, &cloudAPIError{Message: "阿里云产品 endpoint 不能为空"}
	}

	a.clientsMu.RLock()
	client := a.clients[endpoint]
	a.clientsMu.RUnlock()
	if client != nil {
		return client, nil
	}
	if !isAllowedAliyunRegionalEndpoint(endpoint) {
		return nil, &cloudAPIError{Message: "阿里云产品 endpoint 不受支持"}
	}

	a.clientsMu.Lock()
	defer a.clientsMu.Unlock()
	if client = a.clients[endpoint]; client != nil {
		return client, nil
	}
	client, err := buildOpenAPIClient(a.accessKeyID, a.accessKeySecret, endpoint)
	if err != nil {
		return nil, &cloudAPIError{Message: "初始化阿里云地域产品客户端失败", Cause: err}
	}
	a.clients[endpoint] = client
	return client, nil
}

// aliyunRegionalEndpoint 构造官方 regional 规则使用的 ALB/NLB Endpoint。
func aliyunRegionalEndpoint(product, region string) (string, error) {
	normalizedProduct := strings.ToLower(strings.TrimSpace(product))
	normalizedRegion := strings.ToLower(strings.TrimSpace(region))
	if normalizedProduct != "alb" && normalizedProduct != "nlb" {
		return "", fmt.Errorf("不支持的阿里云地域产品")
	}
	if !isSafeAliyunRegionID(normalizedRegion) {
		return "", fmt.Errorf("阿里云地域 ID 无效")
	}
	return normalizedProduct + "." + normalizedRegion + ".aliyuncs.com", nil
}

// isAllowedAliyunRegionalEndpoint 限制动态客户端只能访问合法的 ALB/NLB 地域域名。
func isAllowedAliyunRegionalEndpoint(endpoint string) bool {
	for _, product := range []string{"alb", "nlb"} {
		prefix := product + "."
		const suffix = ".aliyuncs.com"
		if !strings.HasPrefix(endpoint, prefix) || !strings.HasSuffix(endpoint, suffix) {
			continue
		}
		region := strings.TrimSuffix(strings.TrimPrefix(endpoint, prefix), suffix)
		return isSafeAliyunRegionID(region)
	}
	return false
}

// isSafeAliyunRegionID 校验地域为单个安全 DNS 标签，避免 Endpoint 注入。
func isSafeAliyunRegionID(region string) bool {
	if region == "" || len(region) > 63 || region[0] == '-' || region[len(region)-1] == '-' {
		return false
	}
	for _, char := range region {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
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
	requestTimeout := aliyunAPICallTimeout
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		if remaining < requestTimeout {
			requestTimeout = remaining
		}
	}
	milliseconds := max(int(requestTimeout/time.Millisecond), 1)
	runtime.ReadTimeout = &milliseconds
	runtime.ConnectTimeout = &milliseconds

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
