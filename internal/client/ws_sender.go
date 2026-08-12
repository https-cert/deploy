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

// executeBusinessACK 描述客户端返回后端的结构化业务执行结果。
type executeBusinessACK struct {
	Result            deployPB.ExecuteBusinesRequest_RequestResult // Result 是协议层成功、失败或不支持状态。
	Message           string                                       // Message 是可安全返回后端的诊断说明。
	Retryable         bool                                         // Retryable 表示无需修改配置即可重试。
	ProviderRequestID string                                       // ProviderRequestID 是云厂商控制面请求 ID。
}

// sendNotifyRequest 发送 NotifyRequest 消息（基础发送方法）
func (c *WSClient) sendNotifyRequest(req *deployPB.NotifyRequest) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

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
	// 使用较长的超时时间，避免网络慢时误判为失败
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
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
				logger.Warn("获取系统信息失败，跳过本次心跳", "error", err)
				continue // 跳过本次心跳，不要退出整个心跳循环
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

// sendConnectResponse 只发送连接测试状态，不把客户端本地诊断信息发送到后端。
func (c *WSClient) sendConnectResponse(requestId, provider string, businessType deployPB.ExecuteBusinesType, targetRef string, success bool) {
	req := &deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientId,
		Version:   config.Version,
		RequestId: requestId,
		Data: &deployPB.NotifyRequest_ConnectRequest{
			ConnectRequest: &deployPB.ConnectRequest{
				Provider:           provider,
				Success:            success,
				ExecuteBusinesType: businessType,
				TargetRef:          targetRef,
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

// buildExecuteBusinesResponse 构造显式携带重试分类的业务执行 ACK。
func (c *WSClient) buildExecuteBusinesResponse(requestID string, ack executeBusinessACK) *deployPB.NotifyRequest {
	retryable := ack.Retryable
	return &deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientId,
		Version:   config.Version,
		RequestId: requestID,
		Data: &deployPB.NotifyRequest_ExecuteBusinesRequest{
			ExecuteBusinesRequest: &deployPB.ExecuteBusinesRequest{
				RequestResult:     ack.Result,
				Message:           ack.Message,
				Retryable:         &retryable,
				ProviderRequestId: ack.ProviderRequestID,
			},
		},
	}
}

// sendExecuteBusinesResponse 发送结构化业务执行响应。
func (c *WSClient) sendExecuteBusinesResponse(requestID string, ack executeBusinessACK) {
	req := c.buildExecuteBusinesResponse(requestID, ack)

	if err := c.sendNotifyRequest(req); err != nil {
		logger.Error("发送执行业务响应失败", "error", err, "requestId", requestID)
	}
}

// sendChallengeResponse 回传 HTTP-01 challenge 设置或删除结果。
func (c *WSClient) sendChallengeResponse(requestID string, request *deployPB.ChallengeRequest, result deployPB.ChallengeResponse_Result, resultMessage string) {
	if request == nil || requestID == "" {
		logger.Error("无法发送 Challenge ACK", "requestId", requestID, "message", resultMessage)
		return
	}
	req := &deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientId,
		Version:   config.Version,
		RequestId: requestID,
		Data: &deployPB.NotifyRequest_ChallengeResponse{
			ChallengeResponse: &deployPB.ChallengeResponse{
				OperationId: request.OperationId,
				CertId:      request.CertId,
				Domain:      request.Domain,
				Token:       request.Token,
				Result:      result,
				Message:     resultMessage,
			},
		},
	}
	if err := c.sendNotifyRequest(req); err != nil {
		logger.Error("发送 Challenge ACK 失败", "error", err, "requestId", requestID, "operationId", request.OperationId)
	}
}
