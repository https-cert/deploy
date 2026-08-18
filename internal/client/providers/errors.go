package providers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/https-cert/deploy/pb/deployPB"
)

const deploymentFailureMessage = "部署失败，请查看 deploy 客户端日志"

// DeploymentError 描述云资源部署失败的重试属性和云厂商请求编号。
type DeploymentError struct {
	Message   string // Message 可安全返回后端的脱敏错误说明。
	Retryable bool   // Retryable 表示后端是否可以自动重试。
	RequestID string // RequestID 云厂商请求 ID。
	Cause     error  // Cause 保留原始错误链；跨端 ACK 禁止使用，在线日志必须先脱敏。
}

// Error 返回本地诊断信息；跨端回传必须经过 DeploymentErrorInfo 脱敏。
func (e *DeploymentError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "云资源部署失败"
}

// Unwrap 返回原始错误，供 errors.Is 和 errors.As 使用。
func (e *DeploymentError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// NewDeploymentError 创建一个带重试属性的云部署错误。
func NewDeploymentError(message string, retryable bool, requestID string, cause error) error {
	return &DeploymentError{
		Message:   message,
		Retryable: retryable,
		RequestID: requestID,
		Cause:     cause,
	}
}

// RequestID 从结构化部署错误或厂商错误中提取脱敏请求编号。
func RequestID(err error) string {
	if err == nil {
		return ""
	}
	var deploymentError *DeploymentError
	if errors.As(err, &deploymentError) {
		return strings.TrimSpace(deploymentError.RequestID)
	}
	var requestIDError interface{ RequestID() string }
	if errors.As(err, &requestIDError) {
		return strings.TrimSpace(requestIDError.RequestID())
	}
	return ""
}

// IsContextFailure 判断错误是否由调用方取消或超时引起。
func IsContextFailure(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// FailureKind 将错误归类为跨端稳定的部署失败类型。
func FailureKind(err error) deployPB.FailureKind {
	if err == nil {
		return deployPB.FailureKind_FAILURE_KIND_UNSPECIFIED
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return deployPB.FailureKind_FAILURE_KIND_TIMEOUT
	}
	if errors.Is(err, context.Canceled) {
		return deployPB.FailureKind_FAILURE_KIND_CANCELED
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "并发") || strings.Contains(message, "繁忙") || strings.Contains(message, "busy") {
		return deployPB.FailureKind_FAILURE_KIND_BUSY
	}
	if strings.Contains(message, "目标") || strings.Contains(message, "target") || strings.Contains(message, "资源已失效") || strings.Contains(message, "不存在") {
		return deployPB.FailureKind_FAILURE_KIND_TARGET_UNAVAILABLE
	}
	var deploymentError *DeploymentError
	if errors.As(err, &deploymentError) {
		if errors.Is(deploymentError.Cause, context.DeadlineExceeded) {
			return deployPB.FailureKind_FAILURE_KIND_TIMEOUT
		}
		if errors.Is(deploymentError.Cause, context.Canceled) {
			return deployPB.FailureKind_FAILURE_KIND_CANCELED
		}
		return deployPB.FailureKind_FAILURE_KIND_PROVIDER
	}
	return deployPB.FailureKind_FAILURE_KIND_LOCAL_PUBLISH
}

// DeploymentErrorInfo 只提取可返回后端的固定文案和重试分类。
func DeploymentErrorInfo(err error) (message string, retryable bool) {
	if err == nil {
		return "", false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "部署操作超时", true
	}
	if errors.Is(err, context.Canceled) {
		return "部署操作已取消", true
	}

	var deploymentError *DeploymentError
	if errors.As(err, &deploymentError) {
		if errors.Is(deploymentError.Cause, context.DeadlineExceeded) {
			return "部署操作超时", true
		}
		if errors.Is(deploymentError.Cause, context.Canceled) {
			return "部署操作已取消", true
		}
		return deploymentFailureMessage, deploymentError.Retryable
	}
	return deploymentFailureMessage, false
}

// IsPermissionDenied 判断云 SDK 错误码是否明确表示缺少访问权限。
func IsPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	var pointerCodeError interface{ GetCode() *string }
	if errors.As(err, &pointerCodeError) && pointerCodeError.GetCode() != nil {
		return IsPermissionDeniedCode(*pointerCodeError.GetCode())
	}
	var stringCodeError interface{ GetCode() string }
	if errors.As(err, &stringCodeError) {
		return IsPermissionDeniedCode(stringCodeError.GetCode())
	}
	var statusCodeError interface{ GetStatusCode() *int }
	if errors.As(err, &statusCodeError) && statusCodeError.GetStatusCode() != nil {
		return *statusCodeError.GetStatusCode() == http.StatusUnauthorized
	}
	return false
}

// IsPermissionDeniedCode 按明确错误码白名单识别权限不足，避免只凭 HTTP 403 误判。
func IsPermissionDeniedCode(code string) bool {
	normalized := strings.ToLower(strings.TrimSpace(code))
	if normalized == "" {
		return false
	}
	for _, marker := range []string{
		"accessdenied",
		"forbidden",
		"nopermission",
		"operationdenied",
		"permissiondenied",
		"unauthorizedoperation",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
