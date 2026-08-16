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

	return c.sendDeploymentRequest(req)
}

// sendHeartbeat 发送心跳消息
func (c *WSClient) sendHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
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

			if err := c.sendDeploymentRequest(req); err != nil {
				logger.Warn("发送心跳失败，主动关闭连接以触发重连", "error", err, "interval", heartbeatInterval)
				// 主动关闭连接，触发重连机制
				c.connMu.Lock()
				if c.conn != nil {
					c.conn.Close(websocket.StatusAbnormalClosure, "heartbeat failed")
				}
				c.connMu.Unlock()
				return
			}
		}
	}
}

// sendDeploymentRequest 发送 v2 WebSocket 信封。
func (c *WSClient) sendDeploymentRequest(req *deployPB.DeploymentRequest) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()
	if conn == nil {
		return errors.New("连接已关闭")
	}
	data, err := c.protojsonMarshaler.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化 v2 消息失败: %w", err)
	}
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
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
