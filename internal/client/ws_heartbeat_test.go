package client

import (
	"context"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/system"
	"github.com/https-cert/deploy/pb/deployPB"
)

// TestOldHeartbeatCannotTouchNewConnection 模拟旧心跳在重连后才返回，验证它既不写入也不关闭新连接。
func TestOldHeartbeatCannotTouchNewConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	oldConnection, _ := openWebSocketPair(t, ctx)
	newConnection, peer := openWebSocketPair(t, ctx)
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	client := &WSClient{
		ctx: ctx, conn: oldConnection,
		loadSystemInfo: func() (*system.SystemInfo, error) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return &system.SystemInfo{}, nil
		},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.sendHeartbeat(ctx, oldConnection, time.Millisecond)
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("旧心跳未开始")
	}
	_ = oldConnection.CloseNow()
	client.connMu.Lock()
	client.conn = newConnection
	client.connMu.Unlock()
	release <- struct{}{}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("旧心跳未在失败后退出")
	}
	if err := client.sendDeploymentRequest(&deployPB.DeploymentRequest{RequestId: "new-connection"}); err != nil {
		t.Fatalf("旧心跳错误关闭了新连接: %v", err)
	}
	if request := readDeploymentRequest(t, peer); request.GetRequestId() != "new-connection" {
		t.Fatalf("新连接收到了旧心跳: %v", request)
	}
}

// TestBusyResponseDoesNotBlockPong 验证忙碌回包阻塞时读循环仍能回应服务端 Ping。
func TestBusyResponseDoesNotBlockPong(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connection, peer := openWebSocketPair(t, ctx)
	client := &WSClient{ctx: ctx, conn: connection, ops: newOperationRunner(1)}
	client.ops.sem <- struct{}{}
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	service := client.ensureDeployService()
	service.sendEnvelope = func(*deployPB.DeploymentRequest) {
		close(entered)
		<-release
	}
	done := make(chan error, 1)
	go func() { done <- client.handleWSMessages() }()
	writeDeploymentResponse(t, peer, &deployPB.DeploymentResponse{
		Data: &deployPB.DeploymentResponse_TestRequest{TestRequest: &deployPB.DeploymentTestRequest{}},
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("未进入忙碌回包")
	}
	pingCtx, pingCancel := context.WithTimeout(ctx, time.Second)
	defer pingCancel()
	peer.CloseRead(ctx)
	if err := peer.Ping(pingCtx); err != nil {
		t.Fatalf("业务回包阻塞了 Pong: %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("连接循环未退出")
	}
}
