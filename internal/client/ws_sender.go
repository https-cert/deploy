package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// sendNotifyRequest 发送 NotifyRequest 消息（基础发送方法）
func (c *WSClient) sendNotifyRequest(req *deployPB.NotifyRequest) error {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil {
		return errors.New("连接已关闭")
	}

	// 使用 protojson 序列化
	data, err := c.protojsonMarshaler.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %w", err)
	}

	// 发送 JSON 消息（WebSocket Text 消息）
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	return conn.Write(ctx, websocket.MessageText, data)
}

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

	// 发送注册消息（使用 NotifyRequest 格式）
	req := &deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientId,
		Version:   config.Version,
		Data: &deployPB.NotifyRequest_RegisterResponse{
			RegisterResponse: &deployPB.RegisterResponse{
				SystemInfo: &deployPB.RegisterResponse_SystemInfo{
					Os:       sysInfo.OS,
					Arch:     sysInfo.Arch,
					Hostname: sysInfo.Hostname,
					Ip:       sysInfo.IP,
				},
			},
		},
	}

	return c.sendNotifyRequest(req)
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
				logger.Warn("获取系统信息失败", "error", err)
				return
			}

			// 发送心跳消息（使用 RegisterResponse 格式）
			req := &deployPB.NotifyRequest{
				AccessKey: c.accessKey,
				ClientId:  c.clientId,
				Version:   config.Version,
				Data: &deployPB.NotifyRequest_RegisterResponse{
					RegisterResponse: &deployPB.RegisterResponse{
						SystemInfo: &deployPB.RegisterResponse_SystemInfo{
							Os:       systemInfo.OS,
							Arch:     systemInfo.Arch,
							Hostname: systemInfo.Hostname,
							Ip:       systemInfo.IP,
						},
					},
				},
			}

			if err := c.sendNotifyRequest(req); err != nil {
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

// sendConnectResponse 发送连接测试响应
func (c *WSClient) sendConnectResponse(requestId, provider string, success bool) {
	req := &deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientId,
		Version:   config.Version,
		RequestId: requestId,
		Data: &deployPB.NotifyRequest_ConnectRequest{
			ConnectRequest: &deployPB.ConnectRequest{
				Provider: provider,
				Success:  success,
			},
		},
	}

	if err := c.sendNotifyRequest(req); err != nil {
		logger.Warn("发送连接测试响应失败", "error", err)
	}
}

// sendGetProviderResponse 发送获取提供商信息响应
func (c *WSClient) sendGetProviderResponse(requestId string, providers []*deployPB.GetProviderResponse_Provider) {
	req := &deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientId,
		RequestId: requestId,
		Data: &deployPB.NotifyRequest_GetProviderResponse{
			GetProviderResponse: &deployPB.GetProviderResponse{
				Providers: providers,
			},
		},
	}

	if err := c.sendNotifyRequest(req); err != nil {
		logger.Warn("发送获取提供商信息响应失败", "error", err)
	}
}

// sendExecuteBusinesResponse 发送执行业务响应
func (c *WSClient) sendExecuteBusinesResponse(requestId string, result deployPB.ExecuteBusinesRequest_RequestResult) {
	req := &deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientId,
		Version:   config.Version,
		RequestId: requestId,
		Data: &deployPB.NotifyRequest_ExecuteBusinesRequest{
			ExecuteBusinesRequest: &deployPB.ExecuteBusinesRequest{
				RequestResult: result,
			},
		},
	}

	if err := c.sendNotifyRequest(req); err != nil {
		logger.Error("发送执行业务响应失败", "error", err, "requestId", requestId)
	}
}
