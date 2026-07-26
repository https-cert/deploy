package providers

import (
	"errors"
	"fmt"
)

// DeploymentError 描述云资源部署失败的重试属性和云厂商请求编号。
type DeploymentError struct {
	Message   string // Message 可安全返回后端的脱敏错误说明。
	Retryable bool   // Retryable 表示后端是否可以自动重试。
	RequestID string // RequestID 云厂商请求 ID。
	Cause     error  // Cause 原始错误，仅用于本地错误链和日志。
}

// Error 返回脱敏错误说明。
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

// DeploymentErrorInfo 从任意错误中提取可返回后端的结构化信息。
func DeploymentErrorInfo(err error) (message string, retryable bool, requestID string) {
	if err == nil {
		return "", false, ""
	}

	var deploymentError *DeploymentError
	if errors.As(err, &deploymentError) {
		return deploymentError.Error(), deploymentError.Retryable, deploymentError.RequestID
	}
	return fmt.Sprintf("业务执行失败: %v", err), false, ""
}
