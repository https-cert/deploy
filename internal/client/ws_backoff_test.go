package client

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

// TestReconnectDelayAcrossFailures 验证短连接、稳定连接和随后的握手失败共享退避状态。
func TestReconnectDelayAcrossFailures(t *testing.T) {
	client := &WSClient{reconnectDelay: minReconnectDelay}
	tests := []struct {
		name   string        // name 描述本次失败的连接状态。
		uptime time.Duration // uptime 是刚结束连接的存活时长，握手失败为零。
		want   time.Duration // want 是本次失败后的等待时间。
	}{
		{"首次握手失败", 0, 2 * time.Second},
		{"连接立刻断开", time.Second, 4 * time.Second},
		{"随后握手失败", 0, 8 * time.Second},
		{"未达到稳定门槛", stableConnectionThreshold - time.Second, 16 * time.Second},
		{"达到退避上限", 0, maxReconnectDelay},
		{"保持退避上限", 0, maxReconnectDelay},
		{"稳定连接只复位一次", stableConnectionThreshold, 2 * time.Second},
		{"稳定连接后第一次握手失败", 0, 4 * time.Second},
		{"稳定连接后第二次握手失败", 0, 8 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := client.nextReconnectDelay(test.uptime); got != test.want {
				t.Fatalf("重连等待不符: got %v want %v", got, test.want)
			}
		})
	}
}

// TestReconnectLoopDialFailuresBackOff 通过实际连接循环验证连续握手失败的等待时长和取消退出。
func TestReconnectLoopDialFailuresBackOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var attempts []time.Time
		client := &WSClient{
			ctx: ctx, serverURL: "http://deploy.example.test", reconnectDelay: minReconnectDelay,
			wsHTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				attempts = append(attempts, time.Now())
				if len(attempts) == 7 {
					cancel()
				}
				return nil, errors.New("模拟握手失败")
			})},
		}
		client.startWebSocketLoop()
		if len(attempts) != 7 {
			t.Fatalf("实际握手次数不符: %d", len(attempts))
		}
		for i, want := range []time.Duration{2, 4, 8, 16, 30, 30} {
			if got := attempts[i+1].Sub(attempts[i]); got != want*time.Second {
				t.Fatalf("第 %d 次实际重试等待 %v，期望 %v", i+1, got, want*time.Second)
			}
		}
	})
}

// TestWebSocketHandshakeTimeout 模拟代理一直不返回响应，验证握手会按期退出而非永久等待。
func TestWebSocketHandshakeTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &WSClient{
			ctx: context.Background(), serverURL: "http://deploy.example.test",
			wsHTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				<-request.Context().Done()
				return nil, request.Context().Err()
			})},
		}
		started := time.Now()
		if err := client.connect(); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("握手未返回超时: %v", err)
		}
		if elapsed := time.Since(started); elapsed != wsHandshakeTimeout {
			t.Fatalf("握手等待时间不符: %v", elapsed)
		}
	})
}

// TestLogConnectionFailureKeepsRetryState 验证记录故障不改动退避状态，同轮失败不重置故障起点。
func TestLogConnectionFailureKeepsRetryState(t *testing.T) {
	client := &WSClient{reconnectDelay: maxReconnectDelay}
	client.logConnectionFailure(errors.New("boom"), time.Now(), 3*time.Second)
	if client.reconnectDelay != maxReconnectDelay || client.reconnectSince.IsZero() {
		t.Fatal("记录故障改动了退避或遗漏故障起点")
	}
	before := client.reconnectSince
	client.logConnectionFailure(errors.New("again"), time.Now(), time.Second)
	if client.reconnectSince != before {
		t.Fatal("同一轮断线不应重复刷新 reconnectSince")
	}
}
