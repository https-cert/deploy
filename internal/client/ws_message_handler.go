package client

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// deploymentResourceExecutionTimeout 为后端 60 秒等待窗口预留 ACK 发送时间。
const deploymentResourceExecutionTimeout = 55 * time.Second

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

		// 不设置读取超时，让连接保持持久化
		// 依靠心跳机制和 TCP keepalive 来检测连接状态
		_, data, err := conn.Read(c.ctx)

		if err != nil {
			if errors.Is(err, context.Canceled) {
				logger.Info("WebSocket 连接因 context 取消而关闭")
				return nil
			}
			// 使用 CloseStatus 检查正常关闭
			closeStatus := websocket.CloseStatus(err)
			if closeStatus == websocket.StatusNormalClosure {
				logger.Info("WebSocket 连接正常关闭")
				return nil
			}
			// 记录详细的错误信息
			logger.Warn("WebSocket 读取错误", "error", err, "closeStatus", closeStatus)
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
	if resp == nil {
		logger.Warn("忽略空 WebSocket 消息")
		return
	}
	switch resp.Type {
	case deployPB.Type_UNKNOWN:
		return

	case deployPB.Type_CONNECT:
		// 后端建立连接后会发送不带 payload 的欢迎通知；这不是连接测试请求。
		// 只有携带 connectRequest 时才执行 provider 连接测试。
		if resp.Data == nil {
			return
		}
		if connectReq, ok := resp.Data.(*deployPB.NotifyResponse_ConnectRequest); ok {
			if connectReq.ConnectRequest == nil {
				logger.Warn("连接测试消息缺少 payload", "requestId", resp.RequestId)
				c.sendConnectResponse(resp.RequestId, "", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_UNKNOWN, false)
				return
			}
			requestID := resp.RequestId
			data := connectReq.ConnectRequest
			c.runOperation("connect", func() {
				c.sendConnectResponse(requestID, data.Provider, data.ExecuteBusinesType, false)
			}, func() {
				c.handleConnect(requestID, data)
			})
		} else {
			logger.Warn("连接测试消息类型不匹配", "requestId", resp.RequestId)
		}

	case deployPB.Type_CHALLENGE:
		if challengeReq, ok := resp.Data.(*deployPB.NotifyResponse_ChallengeRequest); ok {
			requestID := resp.RequestId
			request := challengeReq.ChallengeRequest
			c.runOperation("challenge", func() {
				c.sendChallengeResponse(requestID, request, deployPB.ChallengeResponse_CHALLENGE_RESULT_FAILED, "客户端业务并发已达上限")
			}, func() { c.handleChallenge(requestID, request) })
		} else if businesResp, ok := resp.Data.(*deployPB.NotifyResponse_ExecuteBusinesResponse); ok {
			c.runOperation("legacy-challenge", nil, func() { c.handleLegacyChallenge(businesResp.ExecuteBusinesResponse) })
		} else {
			logger.Warn("Challenge 消息类型不匹配", "requestId", resp.RequestId)
		}

	case deployPB.Type_EXECUTE_BUSINES:
		if businesResp, ok := resp.Data.(*deployPB.NotifyResponse_ExecuteBusinesResponse); ok {
			requestID := resp.RequestId
			c.runOperation("execute-business", func() {
				c.sendExecuteBusinesResponse(requestID, executeBusinessACK{
					Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED,
					Message:   "客户端业务并发已达上限",
					Retryable: true,
				})
			}, func() { c.handleExecuteBusines(requestID, businesResp.ExecuteBusinesResponse) })
		} else {
			logger.Warn("业务消息类型不匹配", "requestId", resp.RequestId)
		}

	case deployPB.Type_UPDATE_VERSION:
		c.runOperation("update", nil, c.handleUpdate)

	case deployPB.Type_GET_PROVIDER:
		requestID := resp.RequestId
		c.runOperation("get-provider", nil, func() { c.handleGetProvider(requestID) })

	default:
		logger.Warn("未知的消息类型", "type", resp.Type)
	}
}

// handleConnect 处理连接测试
func (c *WSClient) handleConnect(requestId string, data *deployPB.ConnectRequest) {
	if data == nil {
		c.sendConnectResponse(requestId, "", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_UNKNOWN, false)
		return
	}
	// 标记开始执行业务操作
	c.busyOperations.Add(1)
	defer c.busyOperations.Add(-1)

	logger.Info("收到【测试连接】请求", "provider", data.Provider, "businessType", data.ExecuteBusinesType, "requestId", requestId)

	// 使用共享函数测试对应 provider 或本地部署业务。
	success, err := TestDeploymentConnection(data.Provider, data.ExecuteBusinesType)
	if err != nil {
		logger.Error("测试连接失败", "error", err, "provider", data.Provider, "businessType", data.ExecuteBusinesType)
		success = false
	}

	// 只回传成功状态，避免把 SSH 地址、用户名和远端诊断信息发送到后端。
	c.sendConnectResponse(requestId, data.Provider, data.ExecuteBusinesType, success)
}

// handleGetProvider 处理获取提供商信息
func (c *WSClient) handleGetProvider(requestId string) {
	logger.Info("收到【获取提供商信息】请求", "requestID", requestId)

	c.sendGetProviderResponse(requestId, buildProviderDirectory(GetProviderInfo(), config.GetDeploymentResourceDirectory()))
}

// buildProviderDirectory 将脱敏资源按明确业务挂到所属 provider，且不暴露私有定位字段。
func buildProviderDirectory(providerInfos []ProviderInfo, directory []config.DeploymentResourceDirectoryEntry) []*deployPB.GetProviderResponse_Provider {
	responseProviders := make([]*deployPB.GetProviderResponse_Provider, 0, len(providerInfos))
	for _, providerInfo := range providerInfos {
		provider := &deployPB.GetProviderResponse_Provider{
			Name:   providerInfo.Name,
			Remark: providerInfo.Remark,
		}
		businesses := make(map[deployPB.ExecuteBusinesType]*deployPB.GetProviderResponse_Provider_Business)
		for _, entry := range directory {
			if entry.Provider != providerInfo.Name {
				continue
			}
			business := businesses[entry.ExecuteBusinesType]
			if business == nil {
				business = &deployPB.GetProviderResponse_Provider_Business{ExecuteBusinesType: entry.ExecuteBusinesType}
				businesses[entry.ExecuteBusinesType] = business
				provider.Businesses = append(provider.Businesses, business)
			}
			business.Resources = append(business.Resources, &deployPB.DeployResource{
				TargetRef: entry.TargetRef,
				Label:     entry.Label,
				Domain:    entry.Domain,
			})
		}
		responseProviders = append(responseProviders, provider)
	}
	return responseProviders
}

// handleUpdate 处理版本更新
func (c *WSClient) handleUpdate() {
	updateHandler := NewUpdateHandler(c.ctx)
	updateHandler.HandleUpdate()
}

// handleChallenge 执行 HTTP-01 challenge 请求并返回同 requestId 的 ACK。
func (c *WSClient) handleChallenge(requestID string, request *deployPB.ChallengeRequest) {
	result, message := c.executeChallengeRequest(request)
	c.sendChallengeResponse(requestID, request, result, message)
}

// executeChallengeRequest 校验并执行一条设置或删除 challenge 的请求。
func (c *WSClient) executeChallengeRequest(request *deployPB.ChallengeRequest) (deployPB.ChallengeResponse_Result, string) {
	if request == nil {
		return deployPB.ChallengeResponse_CHALLENGE_RESULT_FAILED, "challenge 请求为空"
	}
	canonicalDomain, _, err := deploys.NormalizeDeploymentDomain(request.Domain)
	if request.OperationId <= 0 || request.CertId <= 0 || request.Token == "" {
		return deployPB.ChallengeResponse_CHALLENGE_RESULT_FAILED, "challenge 请求参数不完整"
	}
	if err != nil {
		return deployPB.ChallengeResponse_CHALLENGE_RESULT_FAILED, err.Error()
	}
	if c.httpServer == nil {
		return deployPB.ChallengeResponse_CHALLENGE_RESULT_FAILED, "HTTP-01 服务未初始化"
	}

	switch request.Action {
	case deployPB.ChallengeRequest_CHALLENGE_ACTION_SET:
		if err := c.httpServer.SetChallenge(request.Token, request.KeyAuth, canonicalDomain); err != nil {
			logger.Error("设置 Challenge 失败", "error", err, "operationId", request.OperationId, "certId", request.CertId, "domain", canonicalDomain)
			return deployPB.ChallengeResponse_CHALLENGE_RESULT_FAILED, err.Error()
		}
		logger.Info("设置 Challenge", "operationId", request.OperationId, "certId", request.CertId, "token", request.Token, "domain", canonicalDomain)
		return deployPB.ChallengeResponse_CHALLENGE_RESULT_SUCCESS, "challenge 已缓存"
	case deployPB.ChallengeRequest_CHALLENGE_ACTION_DELETE:
		if err := c.httpServer.RemoveChallenge(request.Token); err != nil {
			logger.Error("删除 Challenge 失败", "error", err, "operationId", request.OperationId, "certId", request.CertId, "domain", canonicalDomain)
			return deployPB.ChallengeResponse_CHALLENGE_RESULT_FAILED, err.Error()
		}
		logger.Info("删除 Challenge", "operationId", request.OperationId, "certId", request.CertId, "token", request.Token, "domain", canonicalDomain)
		return deployPB.ChallengeResponse_CHALLENGE_RESULT_SUCCESS, "challenge 已删除"
	default:
		return deployPB.ChallengeResponse_CHALLENGE_RESULT_NOT_SUPPORTED, "不支持的 challenge 操作"
	}
}

// handleLegacyChallenge 兼容处理旧服务端复用业务消息发送的 challenge。
func (c *WSClient) handleLegacyChallenge(resp *deployPB.ExecuteBusinesResponse) {
	if resp == nil {
		logger.Warn("忽略空旧版 Challenge 消息")
		return
	}
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
		if err := c.httpServer.RemoveChallenge(token); err != nil {
			logger.Error("删除旧版 Challenge 失败", "error", err, "token", token, "domain", domain)
			return
		}
		logger.Info("删除Challenge", "token", token, "domain", domain)
		return
	}

	// 正常情况：缓存新的 challenge
	if err := c.httpServer.SetChallenge(token, challengeResp, domain); err != nil {
		logger.Error("设置旧版 Challenge 失败", "error", err, "token", token, "domain", domain)
		return
	}
	logger.Info("设置Challenge", "token", token, "domain", domain)
}

// handleExecuteBusines 处理执行业务并返回结构化 ACK。
func (c *WSClient) handleExecuteBusines(requestID string, resp *deployPB.ExecuteBusinesResponse) {
	if resp == nil {
		logger.Error("业务消息缺少 payload", "requestId", requestID)
		c.sendExecuteBusinesResponse(requestID, executeBusinessACK{
			Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED,
			Message:   "业务消息缺少 payload",
			Retryable: false,
		})
		return
	}
	// 标记开始执行业务操作
	c.busyOperations.Add(1)
	defer c.busyOperations.Add(-1)

	if c.businessExecutor == nil {
		logger.Error("业务执行器未初始化", "requestId", requestID)
		c.sendExecuteBusinesResponse(requestID, executeBusinessACK{
			Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED,
			Message:   "客户端业务执行器未初始化",
			Retryable: false,
		})
		return
	}

	var ack executeBusinessACK
	if config.IsDeploymentResourceBusiness(resp.ExecuteBusinesType) {
		ack = c.executeDeploymentResourceBusiness(requestID, resp)
	} else {
		ack = c.executeLegacyBusiness(requestID, resp)
	}
	c.sendExecuteBusinesResponse(requestID, ack)
}

// executeDeploymentResourceBusiness 按 provider、明确业务和 targetRef 锁定并执行精确资源部署。
func (c *WSClient) executeDeploymentResourceBusiness(requestID string, resp *deployPB.ExecuteBusinesResponse) executeBusinessACK {
	providerName := strings.TrimSpace(resp.Provider)
	targetRef := strings.TrimSpace(resp.TargetRef)
	if providerName == "" || targetRef == "" {
		return executeBusinessACK{
			Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED,
			Message:   "资源部署请求缺少 provider 或 targetRef",
			Retryable: false,
		}
	}

	releaseTarget := c.lockOperation("deployment-resource\x00" + providerName + "\x00" + resp.ExecuteBusinesType.String() + "\x00" + targetRef)
	defer releaseTarget()

	remarkName := strings.TrimSpace(resp.Domain)
	if remarkName == "" {
		remarkName = targetRef
	}
	remark := remarkName + "_" + time.Now().Format(time.DateTime)
	logger.Info("收到资源部署业务通知", "provider", providerName, "business", resp.ExecuteBusinesType.String(), "targetRef", targetRef, "requestId", requestID)

	baseContext := c.ctx
	if baseContext == nil {
		baseContext = context.Background()
	}
	executionContext, cancel := context.WithTimeout(baseContext, deploymentResourceExecutionTimeout)
	defer cancel()

	result, err := c.businessExecutor.ExecuteWithContext(executionContext, BusinessRequest{
		ProviderName:       providerName,
		ExecuteBusinesType: resp.ExecuteBusinesType,
		TargetRef:          targetRef,
		Domain:             resp.Domain,
		DownloadURL:        resp.Url,
		Remark:             remark,
		CertificatePEM:     resp.Cert,
		PrivateKeyPEM:      resp.Key,
	})
	if err != nil {
		message, retryable, providerRequestID := providers.DeploymentErrorInfo(err)
		logger.Error("资源部署业务执行失败", "error", err, "provider", providerName, "business", resp.ExecuteBusinesType.String(), "targetRef", targetRef, "requestId", requestID, "providerRequestId", providerRequestID)
		return executeBusinessACK{
			Result:            deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED,
			Message:           message,
			Retryable:         retryable,
			ProviderRequestID: providerRequestID,
		}
	}

	return executeBusinessACK{
		Result:            deployPB.ExecuteBusinesRequest_REQUEST_RESULT_SUCCESS,
		Message:           result.Message,
		Retryable:         false,
		ProviderRequestID: result.RequestID,
	}
}

// executeLegacyBusiness 保留已有本地部署和仅上传业务，并继续按规范域名串行。
func (c *WSClient) executeLegacyBusiness(requestID string, resp *deployPB.ExecuteBusinesResponse) executeBusinessACK {
	canonicalDomain, _, err := deploys.NormalizeDeploymentDomain(resp.Domain)
	if err != nil {
		logger.Error("业务域名无效", "error", err, "requestId", requestID)
		return executeBusinessACK{
			Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED,
			Message:   "业务域名无效: " + err.Error(),
			Retryable: false,
		}
	}
	if canonicalDomain == "" {
		return executeBusinessACK{
			Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED,
			Message:   "域名不能为空",
			Retryable: false,
		}
	}

	releaseDomain := c.lockOperation("domain\x00" + canonicalDomain)
	defer releaseDomain()

	providerName := resp.Provider
	remark := canonicalDomain + "_" + time.Now().Format(time.DateTime)
	logger.Info("收到执行业务通知", "provider", providerName, "executeBusinesType", resp.ExecuteBusinesType, "domain", canonicalDomain)

	if providerName == "" {
		// 如果没有指定提供商，使用默认行为：部署到所有配置的目标
		deployer := deploys.NewCertDeployer(c.downloadFile)
		if err := deployer.DeployCertificate(canonicalDomain, resp.Url); err != nil {
			logger.Error("证书部署失败", "error", err, "domain", canonicalDomain)
			return executeBusinessACK{
				Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED,
				Message:   "本地证书部署失败: " + err.Error(),
				Retryable: true,
			}
		}
		logger.Info("证书部署成功", "domain", canonicalDomain)
		return executeBusinessACK{
			Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_SUCCESS,
			Message:   "本地证书部署成功",
			Retryable: false,
		}
	}

	if err := c.businessExecutor.ExecuteBusiness(providerName, resp.ExecuteBusinesType, canonicalDomain, resp.Url, remark, resp.Cert, resp.Key); err != nil {
		logger.Error("业务执行失败", "error", err, "provider", providerName, "domain", canonicalDomain)
		return executeBusinessACK{
			Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED,
			Message:   "业务执行失败: " + err.Error(),
			Retryable: true,
		}
	}
	return executeBusinessACK{
		Result:    deployPB.ExecuteBusinesRequest_REQUEST_RESULT_SUCCESS,
		Message:   "业务执行成功",
		Retryable: false,
	}
}
