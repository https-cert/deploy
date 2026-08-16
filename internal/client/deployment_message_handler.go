package client

import (
	"context"
	"errors"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// hasDeploymentResponsePayload 判断消息是否确实是 deployment v2 信封，避免 protojson 的宽松解析吞掉 v1 消息。
func hasDeploymentResponsePayload(response *deployPB.DeploymentResponse) bool {
	return response != nil && response.GetData() != nil
}

// handleDeploymentResponse 分发服务端下发的 v2 部署请求。
func (c *WSClient) handleDeploymentResponse(response *deployPB.DeploymentResponse) {
	if response == nil {
		return
	}
	switch data := response.GetData().(type) {
	case *deployPB.DeploymentResponse_Register:
		if c.registrationLogged.CompareAndSwap(false, true) {
			logger.Info("deployment v2 注册成功", "protocolVersion", data.Register.GetProtocolVersion(), "clientVersion", data.Register.GetClientVersion())
		}
	case *deployPB.DeploymentResponse_DiscoverRequest:
		requestID := response.GetRequestId()
		c.runOperation("deployment-v2-discover", func() {
			c.sendDeploymentDiscoverResponse(requestID, unavailableDeploymentCapability(data.DiscoverRequest.GetSelector()))
		}, func() {
			c.handleDeploymentDiscoverRequest(requestID, data.DiscoverRequest)
		})
	case *deployPB.DeploymentResponse_TestRequest:
		requestID := deploymentRequestID(response.GetRequestId(), data.TestRequest.GetRequestId())
		c.runOperation("deployment-v2-test", func() {
			c.sendDeploymentTestResponse(requestID, data.TestRequest.GetSelector(), failedDeploymentResult("客户端业务并发已达上限", true))
		}, func() {
			c.handleDeploymentTestRequest(requestID, data.TestRequest)
		})
	case *deployPB.DeploymentResponse_ExecuteRequest:
		requestID := deploymentRequestID(response.GetRequestId(), data.ExecuteRequest.GetRequestId())
		c.runOperation("deployment-v2-execute", func() {
			c.sendDeploymentExecuteResponse(requestID, data.ExecuteRequest.GetSelector(), failedDeploymentResult("客户端业务并发已达上限", true))
		}, func() {
			c.handleDeploymentExecuteRequest(requestID, data.ExecuteRequest)
		})
	case *deployPB.DeploymentResponse_ChallengeRequest:
		requestID := deploymentRequestID(response.GetRequestId(), data.ChallengeRequest.GetRequestId())
		c.runOperation("deployment-v2-challenge", func() {
			c.sendDeploymentChallengeResponse(requestID, data.ChallengeRequest, failedDeploymentResult("客户端业务并发已达上限", true))
		}, func() {
			c.handleDeploymentChallengeRequest(requestID, data.ChallengeRequest)
		})
	case *deployPB.DeploymentResponse_UpdateRequest:
		c.runOperation("deployment-v2-update", nil, func() {
			c.handleDeploymentUpdateRequest(data.UpdateRequest)
		})
	default:
		logger.Warn("忽略未知 deployment v2 消息", "requestId", response.GetRequestId())
	}
}

// handleDeploymentUpdateRequest 执行 v2 客户端更新请求。
func (c *WSClient) handleDeploymentUpdateRequest(request *deployPB.DeploymentUpdateRequest) {
	if request == nil {
		logger.Warn("忽略空的 deployment v2 更新请求")
		return
	}
	logger.Info("收到 deployment v2 更新请求", "version", request.GetVersion())
	updateHandler := NewUpdateHandler(c.ctx)
	updateHandler.HandleUpdate()
}

// handleDeploymentDiscoverRequest 发现一个明确 provider/type 的脱敏资源目录。
func (c *WSClient) handleDeploymentDiscoverRequest(requestID string, request *deployPB.DeploymentDiscoverRequest) {
	selector := request.GetSelector()
	handler, ok := c.deploymentHandler(selector)
	if !ok {
		c.sendDeploymentDiscoverResponse(requestID, unavailableDeploymentCapability(selector))
		return
	}
	capability := handler.Capability()
	if request.GetIncludeResources() {
		catalog := handler.DiscoverResources(deploymentContext(c.ctx))
		if catalog.Error != nil {
			logger.ErrorLocal("deployment v2 资源发现失败", "error", catalog.Error, "provider", selector.GetProvider().String(), "deploymentType", selector.GetDeploymentType().String(), "requestId", requestID)
		}
		capability.ResourceStatus = catalog.Status
		capability.Resources = deploymentResourcesFromProvider(catalog.Resources)
	}
	c.sendDeploymentDiscoverResponse(requestID, capability)
}

// handleDeploymentTestRequest 测试一个尚未保存或已保存的稳定选择器。
func (c *WSClient) handleDeploymentTestRequest(requestID string, request *deployPB.DeploymentTestRequest) {
	selector := request.GetSelector()
	handler, ok := c.deploymentHandler(selector)
	if !ok {
		c.sendDeploymentTestResponse(requestID, selector, unsupportedDeploymentResult("客户端不支持该部署能力"))
		return
	}
	if err := handler.Test(deploymentContext(c.ctx), selector.GetTargetRef()); err != nil {
		message, retryable := providers.DeploymentErrorInfo(err)
		logger.ErrorLocal("deployment v2 目标测试失败", "error", err, "provider", selector.GetProvider().String(), "deploymentType", selector.GetDeploymentType().String(), "requestId", requestID)
		result := failedDeploymentResult(message, retryable)
		result.ProviderRequestId = providerRequestID(err)
		c.sendDeploymentTestResponse(requestID, selector, result)
		return
	}
	c.sendDeploymentTestResponse(requestID, selector, successfulDeploymentResult("目标测试成功", ""))
}

// handleDeploymentExecuteRequest 使用现有成熟执行器完成 v2 证书部署。
func (c *WSClient) handleDeploymentExecuteRequest(requestID string, request *deployPB.DeploymentExecuteRequest) {
	selector := request.GetSelector()
	handler, ok := c.deploymentHandler(selector)
	if !ok {
		c.sendDeploymentExecuteResponse(requestID, selector, unsupportedDeploymentResult("客户端不支持该部署能力"))
		return
	}
	c.busyOperations.Add(1)
	defer c.busyOperations.Add(-1)
	result, err := handler.Deploy(deploymentContext(c.ctx), DeploymentHandlerRequest{
		RequestID:      requestID,
		TargetRef:      selector.GetTargetRef(),
		Domain:         request.GetDomain(),
		DownloadURL:    request.GetUrl(),
		CertificatePEM: request.GetCert(),
		PrivateKeyPEM:  request.GetKey(),
	})
	if err != nil {
		message, retryable := providers.DeploymentErrorInfo(err)
		executionResult := failedDeploymentResult(message, retryable)
		executionResult.ProviderRequestId = providerRequestID(err)
		c.sendDeploymentExecuteResponse(requestID, selector, executionResult)
		return
	}
	c.sendDeploymentExecuteResponse(requestID, selector, successfulDeploymentResult(result.Message, result.RequestID))
}

// handleDeploymentChallengeRequest 使用原生 v2 challenge 请求设置或清理 HTTP-01 响应。
func (c *WSClient) handleDeploymentChallengeRequest(requestID string, request *deployPB.DeploymentChallengeRequest) {
	c.sendDeploymentChallengeResponse(requestID, request, c.executeDeploymentChallenge(request))
}

// executeDeploymentChallenge 校验并执行一条原生 v2 HTTP-01 challenge 请求。
func (c *WSClient) executeDeploymentChallenge(request *deployPB.DeploymentChallengeRequest) *deployPB.DeploymentExecutionResult {
	if request == nil {
		return failedDeploymentResult("HTTP-01 请求为空", false)
	}
	canonicalDomain, _, err := deploys.NormalizeDeploymentDomain(request.GetDomain())
	if request.GetOperationId() <= 0 || request.GetCertId() <= 0 || request.GetToken() == "" {
		return failedDeploymentResult("HTTP-01 请求参数不完整", false)
	}
	if err != nil {
		return failedDeploymentResult("HTTP-01 域名无效", false)
	}
	if c.httpServer == nil {
		return failedDeploymentResult("HTTP-01 服务未初始化", false)
	}
	switch request.GetAction() {
	case deployPB.DeploymentChallengeRequest_ACTION_SET:
		if err := c.httpServer.SetChallenge(request.GetToken(), request.GetKeyAuth(), canonicalDomain); err != nil {
			logger.ErrorLocal("设置 HTTP-01 Challenge 失败", "error", err, "operationId", request.GetOperationId(), "certId", request.GetCertId(), "domain", canonicalDomain)
			return failedDeploymentResult("HTTP-01 设置失败，请查看 deploy 客户端日志", false)
		}
		logger.Info("设置 HTTP-01 Challenge", "operationId", request.GetOperationId(), "certId", request.GetCertId(), "token", request.GetToken(), "domain", canonicalDomain)
		return successfulDeploymentResult("HTTP-01 challenge 已缓存", "")
	case deployPB.DeploymentChallengeRequest_ACTION_DELETE:
		if err := c.httpServer.RemoveChallenge(request.GetToken()); err != nil {
			logger.ErrorLocal("删除 HTTP-01 Challenge 失败", "error", err, "operationId", request.GetOperationId(), "certId", request.GetCertId(), "domain", canonicalDomain)
			return failedDeploymentResult("HTTP-01 清理失败，请查看 deploy 客户端日志", false)
		}
		logger.Info("删除 HTTP-01 Challenge", "operationId", request.GetOperationId(), "certId", request.GetCertId(), "token", request.GetToken(), "domain", canonicalDomain)
		return successfulDeploymentResult("HTTP-01 challenge 已删除", "")
	default:
		return unsupportedDeploymentResult("不支持的 HTTP-01 操作")
	}
}

// deploymentHandler 按 v2 稳定选择器查找唯一 handler。
func (c *WSClient) deploymentHandler(selector *deployPB.DeploymentSelector) (DeploymentHandler, bool) {
	if selector == nil || c == nil || c.deploymentHandlers == nil {
		return nil, false
	}
	return c.deploymentHandlers.Lookup(selector.GetProvider(), selector.GetDeploymentType())
}

// deploymentResourcesFromProvider 将内部资源转换成 v2 脱敏资源。
func deploymentResourcesFromProvider(resources []providers.DeploymentResource) []*deployPB.DeploymentResource {
	result := make([]*deployPB.DeploymentResource, 0, len(resources))
	for _, resource := range resources {
		result = append(result, &deployPB.DeploymentResource{
			TargetRef: resource.TargetRef, Label: resource.Label, Domain: resource.Domain, Domains: append([]string(nil), resource.Domains...),
			Protocol: resource.Protocol, Status: resource.Status, Group: resource.Group, Region: resource.Region, Port: uint32(resource.ListenerPort), Availability: resource.Availability,
		})
	}
	return result
}

// deploymentContext 为单元测试构造的 client 补充可用上下文。
func deploymentContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// deploymentRequestID 优先使用 payload 内 request ID，并兼容信封关联 ID。
func deploymentRequestID(envelopeID, payloadID string) string {
	if payloadID != "" {
		return payloadID
	}
	return envelopeID
}

// successfulDeploymentResult 构造成功结果。
func successfulDeploymentResult(message, providerRequestID string) *deployPB.DeploymentExecutionResult {
	retryable := false
	return &deployPB.DeploymentExecutionResult{Status: deployPB.DeploymentExecutionResult_STATUS_SUCCESS, Message: message, Retryable: &retryable, ProviderRequestId: providerRequestID}
}

// failedDeploymentResult 构造失败结果。
func failedDeploymentResult(message string, retryable bool) *deployPB.DeploymentExecutionResult {
	return &deployPB.DeploymentExecutionResult{Status: deployPB.DeploymentExecutionResult_STATUS_FAILED, Message: message, Retryable: &retryable}
}

// unsupportedDeploymentResult 构造不支持结果。
func unsupportedDeploymentResult(message string) *deployPB.DeploymentExecutionResult {
	retryable := false
	return &deployPB.DeploymentExecutionResult{Status: deployPB.DeploymentExecutionResult_STATUS_NOT_SUPPORTED, Message: message, Retryable: &retryable}
}

// unavailableDeploymentCapability 构造无法发现的能力摘要。
func unavailableDeploymentCapability(selector *deployPB.DeploymentSelector) *deployPB.DeploymentCapability {
	capability := &deployPB.DeploymentCapability{ResourceStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE}
	if selector != nil {
		capability.Provider = selector.GetProvider()
		capability.DeploymentType = selector.GetDeploymentType()
	}
	return capability
}

// providerRequestID 从结构化 provider 错误中提取云厂商请求 ID。
func providerRequestID(err error) string {
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return deploymentError.RequestID
	}
	return ""
}

// sendDeploymentDiscoverResponse 回传资源发现结果。
func (c *WSClient) sendDeploymentDiscoverResponse(requestID string, capability *deployPB.DeploymentCapability) {
	c.sendDeploymentEnvelope(&deployPB.DeploymentRequest{AccessKey: c.accessKey, ClientId: c.clientId, RequestId: requestID, Data: &deployPB.DeploymentRequest_DiscoverResponse{DiscoverResponse: &deployPB.DeploymentDiscoverResponse{Capability: capability}}})
}

// sendDeploymentTestResponse 回传目标测试结果。
func (c *WSClient) sendDeploymentTestResponse(requestID string, selector *deployPB.DeploymentSelector, result *deployPB.DeploymentExecutionResult) {
	c.sendDeploymentEnvelope(&deployPB.DeploymentRequest{AccessKey: c.accessKey, ClientId: c.clientId, RequestId: requestID, Data: &deployPB.DeploymentRequest_TestResponse{TestResponse: &deployPB.DeploymentTestResponse{RequestId: requestID, Selector: selector, Result: result}}})
}

// sendDeploymentExecuteResponse 回传证书部署结果。
func (c *WSClient) sendDeploymentExecuteResponse(requestID string, selector *deployPB.DeploymentSelector, result *deployPB.DeploymentExecutionResult) {
	c.sendDeploymentEnvelope(&deployPB.DeploymentRequest{AccessKey: c.accessKey, ClientId: c.clientId, RequestId: requestID, Data: &deployPB.DeploymentRequest_ExecuteResponse{ExecuteResponse: &deployPB.DeploymentExecuteResponse{RequestId: requestID, Selector: selector, Result: result}}})
}

// sendDeploymentChallengeResponse 回传 HTTP-01 结果。
func (c *WSClient) sendDeploymentChallengeResponse(requestID string, request *deployPB.DeploymentChallengeRequest, result *deployPB.DeploymentExecutionResult) {
	response := &deployPB.DeploymentChallengeResponse{RequestId: requestID, Result: result}
	if request != nil {
		response.OperationId = request.GetOperationId()
		response.CertId = request.GetCertId()
		response.Domain = request.GetDomain()
		response.Token = request.GetToken()
	}
	c.sendDeploymentEnvelope(&deployPB.DeploymentRequest{AccessKey: c.accessKey, ClientId: c.clientId, RequestId: requestID, Data: &deployPB.DeploymentRequest_ChallengeResponse{ChallengeResponse: response}})
}

// sendDeploymentEnvelope 发送一个已经组装好的 v2 客户端响应。
func (c *WSClient) sendDeploymentEnvelope(request *deployPB.DeploymentRequest) {
	if err := c.sendDeploymentRequest(request); err != nil {
		logger.Error("发送 deployment v2 响应失败", "error", err, "requestId", request.GetRequestId())
	}
}
