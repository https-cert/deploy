package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// TestClassifyDeploymentContextError verifies timeout and cancellation become retryable deployment errors.
func TestClassifyDeploymentContextError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{name: "timeout", err: context.DeadlineExceeded, wantMsg: "部署操作超时"},
		{name: "cancel", err: context.Canceled, wantMsg: "部署操作已取消"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := classifyDeploymentContextError(test.err, context.Background())
			if err == nil {
				t.Fatal("classifyDeploymentContextError() returned nil")
			}
			message, retryable := providers.DeploymentErrorInfo(err)
			if message != test.wantMsg || !retryable {
				t.Fatalf("message=%q retryable=%v, want %q/true", message, retryable, test.wantMsg)
			}
			if !errors.Is(err, test.err) {
				t.Fatalf("classified error does not unwrap to %v", test.err)
			}
		})
	}
}

// TestClassifyDeploymentContextErrorAfterSuccessfulReturn 验证底层返回 nil 时仍以已到期 context 为准。
func TestClassifyDeploymentContextErrorAfterSuccessfulReturn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := classifyDeploymentContextError(nil, ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("classifyDeploymentContextError(nil, canceled) = %v, want context.Canceled", err)
	}
	if kind := providers.FailureKind(err); kind != deployPB.FailureKind_FAILURE_KIND_CANCELED {
		t.Fatalf("FailureKind() = %v, want canceled", kind)
	}
}

// TestOperationLockCancellation 验证等待同目标锁时可以由 context 取消并清理引用。
func TestOperationLockCancellation(t *testing.T) {
	client := &WSClient{operationLocks: make(map[string]*resourceOperationLock)}
	release, err := client.lockOperationWithContext(context.Background(), "target")
	if err != nil {
		t.Fatalf("first lock error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := client.lockOperationWithContext(ctx, "target"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting lock error = %v, want deadline exceeded", err)
	}
	release()
	client.operationLocksMu.Lock()
	defer client.operationLocksMu.Unlock()
	if len(client.operationLocks) != 0 {
		t.Fatalf("operation lock table was not cleaned: %#v", client.operationLocks)
	}
}

// TestDeploymentOperationContextTimeout verifies tests can shorten the production operation timeout.
func TestDeploymentOperationContextTimeout(t *testing.T) {
	previousTimeout := deploymentOperationTimeout
	deploymentOperationTimeout = 10 * time.Millisecond
	t.Cleanup(func() {
		deploymentOperationTimeout = previousTimeout
	})

	ctx, cancel := newDeploymentOperationContext(context.Background())
	defer cancel()
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("operation context error = %v, want deadline exceeded", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("operation context did not honor injected timeout")
	}
}
