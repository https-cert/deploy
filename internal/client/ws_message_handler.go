package client

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"
	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// handleWSMessages 处理 WebSocket 消息循环
func (c *WSClient) handleWSMessages() error {
	// 创建心跳上下文，用于停止心跳协程
	heartbeatCtx, cancelHeartbeat := context.WithCancel(c.ctx)
	defer cancelHeartbeat()

	go c.sendHeartbeat(heartbeatCtx)

	defer func() {
		// 关闭连接
		c.connMu.Lock()
		if c.conn != nil {
			c.conn.Close(websocket.StatusNormalClosure, "消息处理结束")
			c.conn = nil
		}
		c.connMu.Unlock()

		// 更新连接状态
		isConnected.Store(false)

		logger.Info("WebSocket 连接已清理")
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
			return errors.New("连接已关闭")
		}

		_, data, err := conn.Read(c.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			// 使用 CloseStatus 检查正常关闭
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				return nil
			}
			return err
		}

		// 解析为 NotifyResponse
		var resp deployPB.NotifyResponse
		if err := c.protojsonUnmarshaler.Unmarshal(data, &resp); err != nil {
			logger.Warn("解析消息失败", "error", err, "data", string(data))
			continue
		}

		if !isConnected.Load() {
			isConnected.Store(true)
			if c.lastDisconnectLogged.Load() {
				logger.Info("重新连接成功")
				c.lastDisconnectLogged.Store(false)
			}
		}

		c.handleMessage(&resp)
	}
}

// handleMessage 处理单个消息（消息分发）
func (c *WSClient) handleMessage(resp *deployPB.NotifyResponse) {
	switch resp.Type {
	case deployPB.Type_UNKNOWN:
		return

	case deployPB.Type_CONNECT:
		if connectReq, ok := resp.Data.(*deployPB.NotifyResponse_ConnectRequest); ok {
			go c.handleConnect(resp.RequestId, connectReq.ConnectRequest)
		}

	case deployPB.Type_CHALLENGE:
		if businesResp, ok := resp.Data.(*deployPB.NotifyResponse_ExecuteBusinesResponse); ok {
			go c.handleChallenge(businesResp.ExecuteBusinesResponse)
		}

	case deployPB.Type_EXECUTE_BUSINES:
		if businesResp, ok := resp.Data.(*deployPB.NotifyResponse_ExecuteBusinesResponse); ok {
			go c.handleExecuteBusines(resp.RequestId, businesResp.ExecuteBusinesResponse)
		}

	case deployPB.Type_UPDATE_VERSION:
		go c.handleUpdate()

	case deployPB.Type_GET_PROVIDER:
		go c.handleGetProvider(resp.RequestId)

	default:
		logger.Warn("未知的消息类型", "type", resp.Type)
	}
}

// handleConnect 处理连接测试
func (c *WSClient) handleConnect(requestId string, data *deployPB.ConnectRequest) {
	// 标记开始执行业务操作
	c.busyOperations.Add(1)
	defer c.busyOperations.Add(-1)

	logger.Info("收到【测试连接提供商】请求", "provider", data.Provider, "requestId", requestId)

	// 使用共享函数测试连接
	success, err := TestProviderConnection(data.Provider)
	if err != nil {
		logger.Error("测试连接失败", "error", err, "provider", data.Provider)
		success = false
	}

	// 发送响应
	c.sendConnectResponse(requestId, data.Provider, success)
}

// handleGetProvider 处理获取提供商信息
func (c *WSClient) handleGetProvider(requestId string) {
	logger.Info("收到【获取提供商信息】请求", "requestID", requestId)

	// 使用共享函数获取提供商信息
	providerInfos := GetProviderInfo()

	// 转换为 protobuf 格式
	var providers []*deployPB.GetProviderResponse_Provider
	for _, p := range providerInfos {
		providers = append(providers, &deployPB.GetProviderResponse_Provider{
			Name:   p.Name,
			Remark: p.Remark,
		})
	}

	// 发送响应
	c.sendGetProviderResponse(requestId, providers)
}

// handleUpdate 处理版本更新
func (c *WSClient) handleUpdate() {
	logger.Info("收到版本更新通知")
	updateHandler := NewUpdateHandler(c.ctx)
	updateHandler.HandleUpdate()
}

// handleChallenge 处理 ACME HTTP-01 challenge
func (c *WSClient) handleChallenge(resp *deployPB.ExecuteBusinesResponse) {
	token := resp.ChallengeToken
	challengeResp := resp.ChallengeResponse
	domain := resp.Domain

	if c.httpServer == nil {
		logger.Error("HTTP 服务器未初始化，无法处理 ACME challenge")
		return
	}

	// 如果 token 为空，忽略
	if token == "" {
		return
	}

	// 如果 challengeResp 为空，表示后端要求删除此 challenge（过期/取消）
	if challengeResp == "" {
		c.httpServer.RemoveChallenge(token)
		logger.Info("删除Challenge", "token", token, "domain", domain)
		return
	}

	// 正常情况：缓存新的 challenge
	c.httpServer.SetChallenge(token, challengeResp, domain)
	logger.Info("设置Challenge", "token", token, "domain", domain)
}

// handleExecuteBusines 处理执行业务
func (c *WSClient) handleExecuteBusines(requestId string, resp *deployPB.ExecuteBusinesResponse) {
	// 标记开始执行业务操作
	c.busyOperations.Add(1)
	defer c.busyOperations.Add(-1)

	providerName := resp.Provider
	executeBusinesType := resp.ExecuteBusinesType
	domain := resp.Domain
	downloadURL := resp.Url
	cert := resp.Cert
	key := resp.Key

	if domain == "" {
		logger.Error("域名不能为空")
		c.sendExecuteBusinesResponse(requestId, deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED)
		return
	}

	// 上传证书备注
	remark := domain + "_" + time.Now().Format(time.DateTime)

	logger.Info("收到执行业务通知", "provider", providerName, "executeBusinesType", executeBusinesType, "domain", domain)

	var result deployPB.ExecuteBusinesRequest_RequestResult

	if providerName == "" {
		// 如果没有指定提供商，使用默认行为：部署到所有配置的目标
		deployer := deploys.NewCertDeployer(c.downloadFile)
		if err := deployer.DeployCertificate(domain, downloadURL); err != nil {
			logger.Error("证书部署失败", "error", err, "domain", domain)
			result = deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
		} else {
			logger.Info("证书部署成功", "domain", domain)
			result = deployPB.ExecuteBusinesRequest_REQUEST_RESULT_SUCCESS
		}
	} else {
		// 根据提供商执行相应的业务逻辑
		err := c.businessExecutor.ExecuteBusiness(providerName, executeBusinesType, domain, downloadURL, remark, cert, key)
		if err != nil {
			logger.Error("业务执行失败", "error", err, "provider", providerName, "domain", domain)
			result = deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
		} else {
			result = deployPB.ExecuteBusinesRequest_REQUEST_RESULT_SUCCESS
		}
	}

	// 发送执行业务响应
	c.sendExecuteBusinesResponse(requestId, result)
}
