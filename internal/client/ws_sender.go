package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/internal/system"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// sendRegister 发送注册消息
func (c *WSClient) sendRegister() error {
	sysInfo, err := c.getSystemInfo()
	if err != nil {
		return fmt.Errorf("获取系统信息失败: %w", err)
	}

	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil {
		return errors.New("连接已关闭")
	}

	req := &deployPB.DeploymentRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientId,
		Data:      &deployPB.DeploymentRequest_Register{Register: c.buildDeploymentRegistration(sysInfo)},
	}

	return c.sendDeploymentRequestOnConnection(c.ctx, conn, req)
}

// sendHeartbeat 只为传入的连接发送心跳，旧连接的失败不能关闭重连后的连接。
func (c *WSClient) sendHeartbeat(ctx context.Context, conn *websocket.Conn, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			// 获取系统信息用于心跳
			systemInfo, err := c.getSystemInfo()
			if err != nil {
				logger.Warn("获取系统信息失败，跳过本次心跳", "error", err)
				continue // 跳过本次心跳，不要退出整个心跳循环
			}

			// v2 心跳携带最新系统摘要和能力目录，服务端可据此刷新客户端能力。
			req := &deployPB.DeploymentRequest{
				AccessKey: c.accessKey,
				ClientId:  c.clientId,
				Data:      &deployPB.DeploymentRequest_Heartbeat{Heartbeat: &deployPB.DeploymentHeartbeat{Registration: c.buildDeploymentRegistration(systemInfo)}},
			}

			if err := c.sendDeploymentRequestOnConnection(ctx, conn, req); err != nil {
				if ctx.Err() == nil {
					logger.Warn("发送心跳失败，主动关闭连接以触发重连", "error", err, "interval", interval)
				}
				// 写超时后底层连接已不可复用；1006 不能作为线上关闭帧发送。
				_ = conn.CloseNow()
				return
			}
		}
	}
}

// sendDeploymentRequest 发送 v2 WebSocket 信封。
func (c *WSClient) sendDeploymentRequest(req *deployPB.DeploymentRequest) error {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()
	return c.sendDeploymentRequestOnConnection(c.ctx, conn, req)
}

// sendDeploymentRequestOnConnection 将写入绑定到连接和 context。
// coder/websocket 自身会串行化 Write，避免全局写锁让旧连接阻塞新连接注册。
func (c *WSClient) sendDeploymentRequestOnConnection(ctx context.Context, conn *websocket.Conn, req *deployPB.DeploymentRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if conn == nil {
		return errors.New("连接已关闭")
	}
	data, err := c.protojsonMarshaler.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化 v2 消息失败: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, data)
}

// buildDeploymentRegistration 构造原生 v2 注册能力摘要。
func (c *WSClient) buildDeploymentRegistration(sysInfo *system.SystemInfo) *deployPB.DeploymentRegisterV2 {
	capabilities := c.deploymentHandlers.Capabilities()
	registration := &deployPB.DeploymentRegisterV2{ProtocolVersion: 2, ClientVersion: config.Version, Features: []string{"deployment.v2", "deployment.challenge"}, Capabilities: capabilities}
	if sysInfo != nil {
		registration.Os = sysInfo.OS
		registration.Arch = sysInfo.Arch
		registration.Hostname = sysInfo.Hostname
		registration.Ip = sysInfo.IP
	}
	return registration
}
