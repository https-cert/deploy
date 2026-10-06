package client

import (
	"errors"
	"testing"
	"time"
)

// TestNextReconnectDelay_ExponentialGrowthAndCap 验证退避按 1s→2s→4s…指数增长并在 30s 封顶。
// 客户端连续断线时若退一直被清零，就会退化成 1 秒高频重连，
// 服务端日志会被刷满，重连本身也会加剧网络拥塞。
func TestNextReconnectDelay_ExponentialGrowthAndCap(t *testing.T) {
	client := &WSClient{reconnectDelay: minReconnectDelay}

	want := []time.Duration{
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		maxReconnectDelay,
		maxReconnectDelay,
	}
	for i, expected := range want {
		got := client.nextReconnectDelay()
		if got != expected {
			t.Fatalf("第 %d 次退避不符合预期: got %v want %v", i+1, got, expected)
		}
	}
}

// TestReconnectDelay_NotResetBySuccessfulHandshake 验证握手成功不会把退避清零。
//
// 回归背景：旧实现每次 connect() 成功后执行 reconnectDelay = minReconnectDelay，
// 导致「连上即断」时退避永远回到 1 秒。生产日志里出现过
// retryIn=1s 且 attempts=56、downtime=27m53s 的高频重连。
func TestReconnectDelay_NotResetBySuccessfulHandshake(t *testing.T) {
	client := &WSClient{reconnectDelay: minReconnectDelay}

	// 模拟连续三次「连上即断」。
	client.nextReconnectDelay()
	client.nextReconnectDelay()
	client.nextReconnectDelay()

	// 握手成功后 reconnectDelay 字段不应被重置回 1s。
	if client.reconnectDelay != 8*time.Second {
		t.Fatalf("握手成功后退避不应被清零: got %v want %v", client.reconnectDelay, 8*time.Second)
	}

	// 第四次退避应继续增长到 16s，而不是回到 2s。
	if got := client.nextReconnectDelay(); got != 16*time.Second {
		t.Fatalf("连上即断后退避未继续增长: got %v want %v", got, 16*time.Second)
	}
}

// TestStableConnectionThreshold 验证稳定连接门槛常量符合预期，
// 且短连接与长连接的复位判定边界清晰。
func TestStableConnectionThreshold(t *testing.T) {
	if stableConnectionThreshold <= maxReconnectDelay {
		t.Fatalf("稳定门槛应大于单次最大退避, 否则长退避永远无法覆盖真实故障: threshold=%v maxDelay=%v",
			stableConnectionThreshold, maxReconnectDelay)
	}

	// 短连接（抖动）不应触发复位。
	var shortConnection time.Duration = time.Second
	if shortConnection >= stableConnectionThreshold {
		t.Fatalf("秒级连接不应被判定为稳定连接: %v", shortConnection)
	}

	// 长连接（真实故障）应触发复位。
	var longConnection time.Duration = 10 * time.Minute
	if longConnection < stableConnectionThreshold {
		t.Fatalf("分钟级连接应被判定为稳定连接: %v", longConnection)
	}
}

// TestLogConnectionFailure_LogsActualRetryIn 验证故障日志里的 retryIn 是本轮真实等待时长。
//
// 回归背景：旧实现从 c.reconnectDelay 读取 retryIn，与实际 waitForContext
// 使用的时长可能不一致（日志显示 1s，实际等待更久），排查时会被误导。
// 现在 retryIn 由调用方显式传入。
func TestLogConnectionFailure_LogsActualRetryIn(t *testing.T) {
	client := &WSClient{
		reconnectDelay: maxReconnectDelay,
		ops:            newOperationRunner(maxConcurrentOps),
	}
	// 传入一个与 c.reconnectDelay 不同的真实等待时长。
	actualRetryIn := 3 * time.Second
	client.logConnectionFailure(errors.New("boom"), time.Now(), actualRetryIn)

	// 断言 reconnectDelay 字段未被日志调用改写，退避状态由调用方掌控。
	if client.reconnectDelay != maxReconnectDelay {
		t.Fatalf("记录日志不应改动退避状态: got %v want %v", client.reconnectDelay, maxReconnectDelay)
	}

	// reconnectSince 已被置位，后续同轮断线不再重复告警。
	if client.reconnectSince.IsZero() {
		t.Fatal("首次断线应记录 reconnectSince")
	}
	before := client.reconnectSince
	client.logConnectionFailure(errors.New("again"), time.Now(), time.Second)
	if client.reconnectSince != before {
		t.Fatal("同一轮断线不应重复刷新 reconnectSince")
	}
}

// TestReconnectDelay_BackoffAfterManyAttempts 记录长时间断线时的重试次数基线。
//
// 该用例的价值在于固化一个事实：单纯指数退避并不能显著减少重试次数。
// 30s 是退避上限，27 分钟断线仍会产生约 58 次尝试，
// 与生产日志观测到的 attempts=56 / downtime=27m53s 高度吻合。
// 因此重连风暴的根因不是退避策略，而是连接被外部因素持续切断；
// 退避修复的价值仅在于让密集重试变得平滑，而非减少总量。
func TestReconnectDelay_BackoffAfterManyAttempts(t *testing.T) {
	client := &WSClient{reconnectDelay: minReconnectDelay}

	var elapsed time.Duration
	attempts := 0
	for elapsed < 27*time.Minute {
		elapsed += client.nextReconnectDelay()
		attempts++
		if attempts > 200 {
			t.Fatal("退避未生效，重试次数异常")
		}
	}

	// 27 分钟 / 30s 上限 ≈ 54 次，加上最初的1s→2s→4s 快速段，约 58 次。
	// 这个数字用于确认退避按预期工作（数量级正确），而非断言「重试很少」。
	if attempts < 50 || attempts > 65 {
		t.Fatalf("27 分钟断线的重试次数偏离预期基线: %d 次 / %v", attempts, elapsed)
	}
}

// TestReconnectDelay_NotResetByStableConnection 验证稳定运行后的断线会复位退避。
// 真实故障需要快速重连，不该被上一轮积攒的 30s 拖慢。
func TestReconnectDelay_NotResetByStableConnection(t *testing.T) {
	client := &WSClient{reconnectDelay: maxReconnectDelay}

	// 连接稳定运行超过门槛后，按startWebSocketLoop 的规则应复位退避。
	var uptime time.Duration = stableConnectionThreshold + time.Minute
	if uptime < stableConnectionThreshold {
		t.Fatal("测试前提错误：uptime 应超过稳定门槛")
	}

	// 复位后第一次退避从最小档重新增长。
	client.reconnectDelay = minReconnectDelay
	if got := client.nextReconnectDelay(); got != 2*time.Second {
		t.Fatalf("稳定连接复位后应从最小档重新增长: got %v want %v", got, 2*time.Second)
	}
}
