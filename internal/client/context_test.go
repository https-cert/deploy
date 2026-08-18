package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
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
