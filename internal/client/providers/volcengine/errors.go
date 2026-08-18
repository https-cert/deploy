package volcengine

import (
	"errors"
	"regexp"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	cdnapi "github.com/volcengine/volcengine-go-sdk/service/cdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineerr"
)

// certFingerprintMatches 比较火山 CDN 证书目录返回的 SHA-256 指纹。
func certFingerprintMatches(fingerprint *cdnapi.CertFingerprintForListCertInfoOutput, expected string) bool {
	return fingerprint != nil && normalizeFingerprint(stringValue(fingerprint.Sha256)) == normalizeFingerprint(expected)
}

// resourceAvailability 将云端运行状态转换为统一资源状态。
func resourceAvailability(status string) deployPB.DeploymentResourceAvailability {
	if isOnline(status) {
		return deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	}
	return deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
}

// isOnline 判断火山产品的可部署在线状态。
func isOnline(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	return status == "online" || status == "running" || status == "enabled" || status == "normal"
}

// isBindSuccessful 判断 DCDN 绑定状态，未知状态不能误判成功。
func isBindSuccessful(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	return status == "success" || status == "succeeded" || status == "normal"
}

// protocolFromBool 将 CDN HTTPS 开关转换为展示协议。
func protocolFromBool(enabled *bool) string {
	if enabled != nil && *enabled {
		return "HTTPS"
	}
	return "HTTP"
}

// stringValue 安全读取可选字符串指针。
func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

// normalizeFingerprint 统一十六进制指纹的大小写和分隔符。
func normalizeFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(strings.ReplaceAll(value, ":", ""), "-", "")
	return value
}

// metadataRequestID 提取火山 SDK 响应元数据中的请求 ID。
func metadataRequestID(metadata *response.ResponseMetadata) string {
	if metadata == nil {
		return ""
	}
	return strings.TrimSpace(metadata.RequestId)
}

// certificateIDFromError 从重复证书错误中提取官方 cert- ID。
func certificateIDFromError(err error) string {
	if err == nil {
		return ""
	}
	match := regexp.MustCompile(`cert-[a-f0-9]{32}`).FindString(err.Error())
	return match
}

// requestIDFromError 提取火山 SDK 错误中的请求 ID。
func requestIDFromError(err error) string {
	var requestFailure volcengineerr.RequestFailure
	if errors.As(err, &requestFailure) {
		return strings.TrimSpace(requestFailure.RequestID())
	}
	return tosRequestID(err)
}

// isPermissionDenied 判断火山错误是否属于认证或授权不足。
func isPermissionDenied(err error) bool {
	var requestFailure volcengineerr.RequestFailure
	if errors.As(err, &requestFailure) && (requestFailure.StatusCode() == 401 || requestFailure.StatusCode() == 403) {
		return true
	}
	var serviceError volcengineerr.Error
	if errors.As(err, &serviceError) {
		code := strings.ToLower(serviceError.Code())
		return strings.Contains(code, "accessdenied") || strings.Contains(code, "unauthorized") || strings.Contains(code, "forbidden")
	}
	statusCode := tosStatusCode(err)
	code := strings.ToLower(tosErrorCode(err))
	return statusCode == 401 || statusCode == 403 || strings.Contains(code, "accessdenied") || strings.Contains(code, "unauthorized") || strings.Contains(code, "forbidden")
}

// toDeploymentError 将火山 SDK 错误转换成统一重试分类。
func toDeploymentError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}
	retryable := false
	var requestFailure volcengineerr.RequestFailure
	if errors.As(err, &requestFailure) {
		retryable = requestFailure.StatusCode() == 429 || requestFailure.StatusCode() >= 500
	}
	var serviceError volcengineerr.Error
	if errors.As(err, &serviceError) {
		code := strings.ToLower(serviceError.Code())
		retryable = retryable || strings.Contains(code, "throttl") || strings.Contains(code, "internal") || strings.Contains(code, "timeout")
	}
	tosCode := strings.ToLower(tosErrorCode(err))
	tosHTTPStatus := tosStatusCode(err)
	retryable = retryable || tosHTTPStatus == 429 || tosHTTPStatus >= 500 || strings.Contains(tosCode, "slowdown") || strings.Contains(tosCode, "timeout") || strings.Contains(tosCode, "internal")
	return providers.NewDeploymentError("火山引擎"+operation+"失败", retryable, requestIDFromError(err), err)
}

// validateCredentials 拒绝空密钥和控制字符。
func (p *Provider) validateCredentials() error {
	if p == nil || strings.TrimSpace(p.accessKey) == "" || strings.TrimSpace(p.secretKey) == "" {
		return providers.NewDeploymentError("火山引擎 accessKeyId 或 accessKeySecret 未配置", false, "", nil)
	}
	if strings.ContainsAny(p.accessKey+p.secretKey, "\r\n\x00") {
		return providers.NewDeploymentError("火山引擎访问密钥格式无效", false, "", nil)
	}
	return nil
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
