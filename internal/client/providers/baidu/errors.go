package baidu

import (
	"errors"
	"net/http"
	"strings"

	"github.com/baidubce/bce-sdk-go/bce"
	"github.com/https-cert/deploy/internal/client/providers"
)

// validateCredentials 拒绝空凭据和可能污染签名输入的控制字符。
func (p *Provider) validateCredentials() error {
	if p == nil || strings.TrimSpace(p.accessKey) == "" || strings.TrimSpace(p.secretKey) == "" {
		return providers.NewDeploymentError("百度云 accessKeyId 或 accessKeySecret 未配置", false, "", nil)
	}
	if strings.ContainsAny(p.accessKey+p.secretKey, "\r\n\x00") {
		return providers.NewDeploymentError("百度云访问密钥格式无效", false, "", nil)
	}
	return nil
}

// isPermissionDenied 判断百度云凭据无效或权限不足错误。
func isPermissionDenied(err error) bool {
	var serviceError *bce.BceServiceError
	if !errors.As(err, &serviceError) {
		return false
	}
	return serviceError.StatusCode == http.StatusUnauthorized || serviceError.StatusCode == http.StatusForbidden ||
		serviceError.Code == bce.EACCESS_DENIED || serviceError.Code == bce.EINVALID_ACCESS_KEY_ID ||
		serviceError.Code == bce.ESIGNATURE_DOES_NOT_MATCH
}

// requestIDFromError 从百度云服务错误中提取请求 ID。
func requestIDFromError(err error) string {
	var serviceError *bce.BceServiceError
	if errors.As(err, &serviceError) {
		return strings.TrimSpace(serviceError.RequestId)
	}
	return ""
}

// toDeploymentError 将百度云 SDK 错误转换为统一的重试和请求 ID 分类。
func toDeploymentError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}
	var serviceError *bce.BceServiceError
	if errors.As(err, &serviceError) {
		retryable := serviceError.StatusCode == http.StatusTooManyRequests || serviceError.StatusCode >= http.StatusInternalServerError || serviceError.Code == bce.EINTERNAL_ERROR
		return providers.NewDeploymentError("百度云"+operation+"失败", retryable, strings.TrimSpace(serviceError.RequestId), err)
	}
	return providers.NewDeploymentError("百度云"+operation+"失败", false, "", err)
}
