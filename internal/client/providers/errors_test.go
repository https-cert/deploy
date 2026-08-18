package providers

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// requestIDTestError 提供结构化请求 ID。
type requestIDTestError struct {
	requestID string // requestID 是测试请求编号。
}

// Error 返回测试错误文本。
func (e requestIDTestError) Error() string { return "request id error" }

// RequestID 返回测试请求编号。
func (e requestIDTestError) RequestID() string { return e.requestID }

// pointerCodeTestError 提供指针形式的厂商错误码。
type pointerCodeTestError struct {
	code string // code 是测试错误码。
}

// Error 返回测试错误文本。
func (e pointerCodeTestError) Error() string { return e.code }

// GetCode 返回指针形式的测试错误码。
func (e pointerCodeTestError) GetCode() *string { return &e.code }

// stringCodeTestError 提供字符串形式的厂商错误码。
type stringCodeTestError struct {
	code string // code 是测试错误码。
}

// Error 返回测试错误文本。
func (e stringCodeTestError) Error() string { return e.code }

// GetCode 返回字符串形式的测试错误码。
func (e stringCodeTestError) GetCode() string { return e.code }

// statusCodeTestError 提供 HTTP 状态码。
type statusCodeTestError struct {
	status int // status 是测试 HTTP 状态码。
}

// Error 返回测试错误文本。
func (e statusCodeTestError) Error() string { return http.StatusText(e.status) }

// GetStatusCode 返回测试 HTTP 状态码。
func (e statusCodeTestError) GetStatusCode() *int { return &e.status }

// TestDeploymentErrorBehavior 验证结构化部署错误的文本、解包和请求 ID。
func TestDeploymentErrorBehavior(t *testing.T) {
	cause := errors.New("cause")
	deploymentError := NewDeploymentError("safe message", true, " request-1 ", cause)
	if deploymentError.Error() != "safe message" || !errors.Is(deploymentError, cause) || RequestID(deploymentError) != "request-1" {
		t.Fatalf("结构化部署错误行为不匹配: err=%v requestID=%q", deploymentError, RequestID(deploymentError))
	}
	if RequestID(requestIDTestError{requestID: " request-2 "}) != "request-2" || RequestID(nil) != "" {
		t.Fatal("通用请求 ID 提取失败")
	}
	if (&DeploymentError{Cause: cause}).Error() != "cause" || (&DeploymentError{}).Error() != "云资源部署失败" {
		t.Fatal("部署错误回退文本不匹配")
	}
	var nilError *DeploymentError
	if nilError.Error() != "" || nilError.Unwrap() != nil {
		t.Fatal("nil 部署错误应安全返回")
	}
}

// TestDeploymentErrorInfo 验证 context 和普通部署错误的脱敏重试分类。
func TestDeploymentErrorInfo(t *testing.T) {
	tests := []struct {
		name          string // name 是子测试名称。
		err           error  // err 是待分类错误。
		wantMessage   string // wantMessage 是期望安全文本。
		wantRetryable bool   // wantRetryable 是期望重试属性。
	}{
		{name: "nil"},
		{name: "超时", err: context.DeadlineExceeded, wantMessage: "部署操作超时", wantRetryable: true},
		{name: "取消", err: context.Canceled, wantMessage: "部署操作已取消", wantRetryable: true},
		{name: "包装超时", err: NewDeploymentError("ignored", false, "", context.DeadlineExceeded), wantMessage: "部署操作超时", wantRetryable: true},
		{name: "包装取消", err: NewDeploymentError("ignored", false, "", context.Canceled), wantMessage: "部署操作已取消", wantRetryable: true},
		{name: "可重试部署错误", err: NewDeploymentError("private", true, "", errors.New("cause")), wantMessage: deploymentFailureMessage, wantRetryable: true},
		{name: "普通错误", err: errors.New("private"), wantMessage: deploymentFailureMessage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, retryable := DeploymentErrorInfo(test.err)
			if message != test.wantMessage || retryable != test.wantRetryable {
				t.Fatalf("错误分类不匹配: message=%q retryable=%v", message, retryable)
			}
		})
	}
	if !IsContextFailure(context.Canceled) || !IsContextFailure(context.DeadlineExceeded) || IsContextFailure(errors.New("other")) {
		t.Fatal("context 错误识别不匹配")
	}
}

// TestPermissionDeniedClassification 验证厂商错误码白名单和 HTTP 401 分类。
func TestPermissionDeniedClassification(t *testing.T) {
	for _, err := range []error{
		pointerCodeTestError{code: "AccessDenied"},
		stringCodeTestError{code: "AuthFailure.UnauthorizedOperation"},
		statusCodeTestError{status: http.StatusUnauthorized},
	} {
		if !IsPermissionDenied(err) {
			t.Fatalf("权限错误未识别: %T %v", err, err)
		}
	}
	for _, err := range []error{nil, stringCodeTestError{code: "InternalError"}, statusCodeTestError{status: http.StatusForbidden}} {
		if IsPermissionDenied(err) {
			t.Fatalf("非白名单错误被误判为权限不足: %v", err)
		}
	}
	for _, code := range []string{"AccessDenied", "NoPermission", "OperationDenied", "PermissionDenied", "UnauthorizedOperation", "Forbidden"} {
		if !IsPermissionDeniedCode(code) {
			t.Fatalf("权限码未识别: %q", code)
		}
	}
	if IsPermissionDeniedCode("") || IsPermissionDeniedCode("InternalError") {
		t.Fatal("非权限码被误判")
	}
}
