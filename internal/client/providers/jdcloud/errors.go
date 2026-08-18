package jdcloud

import (
	"errors"
	"fmt"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/jdcloud-api/jdcloud-sdk-go/core"
	cdnapi "github.com/jdcloud-api/jdcloud-sdk-go/services/cdn/apis"
	sslapi "github.com/jdcloud-api/jdcloud-sdk-go/services/ssl/apis"
)

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
