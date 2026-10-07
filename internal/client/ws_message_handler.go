package client

import (
	"context"
	"errors"
	"time"

	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// handleWSMessages 处理纯 v2 WebSocket 消息循环。
func (c *WSClient) handleWSMessages() error {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()
	if conn == nil {
		return errors.New("WebSocket v2 连接已关闭")
	}

	heartbeatCtx, cancelHeartbeat := context.WithCancel(c.ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		c.sendHeartbeat(heartbeatCtx, conn, heartbeatInterval)
	}()

	defer func() {
		// 先停止本连接的心跳和写入，再允许重连，旧任务不能操作下一条连接。
		cancelHeartbeat()
		_ = conn.CloseNow()
		<-heartbeatDone
		c.connMu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		c.connMu.Unlock()
		c.connected.Store(false)
	}()

	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}

		_, data, err := conn.Read(c.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			// 保留正常关闭帧的 reason，以区分连接替换、服务端退出与网络故障。
			return err
		}

		var response deployPB.DeploymentResponse
		if err := c.protojsonUnmarshaler.Unmarshal(data, &response); err != nil {
			logger.Warn("解析 deployment v2 消息失败", "error", err)
			continue
		}
		if !hasDeploymentResponsePayload(&response) {
			logger.Warn("忽略缺少 payload 的 deployment v2 消息", "requestId", response.GetRequestId())
			continue
		}
		if c.connected.CompareAndSwap(false, true) {
			c.logConnectionRecovery(time.Now())
		}
		// 常规业务已由 operationRunner 异步执行，但满载时的 onBusy 会同步回包，
		// 等待网络写入也会阻塞分发。保持异步入口，确保读循环持续处理 Ping 并回复 Pong。
		go c.handleDeploymentResponse(&response)
	}
}
