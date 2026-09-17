package client

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// handleWSMessages 处理纯 v2 WebSocket 消息循环。
func (c *WSClient) handleWSMessages() error {
	heartbeatCtx, cancelHeartbeat := context.WithCancel(c.ctx)
	defer cancelHeartbeat()
	go c.sendHeartbeat(heartbeatCtx)

	defer func() {
		c.connMu.Lock()
		if c.conn != nil {
			_ = c.conn.Close(websocket.StatusNormalClosure, "消息处理结束")
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

		c.connMu.Lock()
		conn := c.conn
		c.connMu.Unlock()
		if conn == nil {
			return errors.New("WebSocket v2 连接已关闭")
		}

		_, data, err := conn.Read(c.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			closeStatus := websocket.CloseStatus(err)
			if closeStatus == websocket.StatusNormalClosure {
				return nil
			}
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
		c.handleDeploymentResponse(&response)
	}
}
