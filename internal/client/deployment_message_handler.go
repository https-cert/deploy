package client

import (
	"context"
	"errors"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// hasDeploymentResponsePayload 判断消息是否确实是 deployment v2 信封，避免 protojson 的宽松解析吞掉 v1 消息。
func hasDeploymentResponsePayload(response *deployPB.DeploymentResponse) bool {
	return response != nil && response.GetData() != nil
}

// handleDeploymentResponse 分发服务端下发的 v2 部署请求到部署服务。
func (c *WSClient) handleDeploymentResponse(response *deployPB.DeploymentResponse) {
	if response == nil {
		return
	}
	c.ensureDeployService().HandleResponse(response)
}

// deploymentResourcesFromProvider 将内部资源转换成 v2 脱敏资源。
func deploymentResourcesFromProvider(resources []providers.DeploymentResource) []*deployPB.DeploymentResource {
	result := make([]*deployPB.DeploymentResource, 0, len(resources))
	for _, resource := range resources {
		result = append(result, &deployPB.DeploymentResource{
			TargetRef: resource.TargetRef, Label: resource.Label, Domain: resource.Domain, Domains: append([]string(nil), resource.Domains...),
			SiteDomain: resource.SiteDomain,
			Protocol:   resource.Protocol, Status: resource.Status, Group: resource.Group, Region: resource.Region, Port: uint32(resource.ListenerPort), Availability: resource.Availability,
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

// executeDeploymentChallenge 兼容入口：将 challenge 请求交给部署服务执行。
func (c *WSClient) executeDeploymentChallenge(request *deployPB.DeploymentChallengeRequest) *deployPB.DeploymentExecutionResult {
	return c.ensureDeployService().executeChallenge(request)
}

func (c *WSClient) handleDeploymentTestRequest(requestID string, request *deployPB.DeploymentTestRequest) {
	c.ensureDeployService().handleTestRequest(requestID, request)
}

func (c *WSClient) handleDeploymentExecuteRequest(requestID string, request *deployPB.DeploymentExecuteRequest) {
	c.ensureDeployService().handleExecuteRequest(requestID, request)
}

func (c *WSClient) handleDeploymentDiscoverRequest(requestID string, request *deployPB.DeploymentDiscoverRequest) {
	c.ensureDeployService().handleDiscoverRequest(requestID, request)
}

func (c *WSClient) handleDeploymentUpdateRequest(request *deployPB.DeploymentUpdateRequest) {
	c.ensureDeployService().handleUpdateRequest(request)
}

// deploymentHandler 按 v2 稳定选择器查找唯一 handler。
func (c *WSClient) deploymentHandler(selector *deployPB.DeploymentSelector) (DeploymentHandler, bool) {
	if selector == nil || c == nil || c.deploymentHandlers == nil {
		return nil, false
	}
	return c.deploymentHandlers.Lookup(selector.GetProvider(), selector.GetDeploymentType())
}

func (c *WSClient) ensureDeployService() *deploymentService {
	c.serviceMu.Lock()
	defer c.serviceMu.Unlock()
	if c.deployService == nil {
		c.deployService = newDeploymentService(c)
	}
	return c.deployService
}

// newDeploymentOperationContext 为每次 v2 业务创建受客户端生命周期约束的 55 秒操作上下文。
func newDeploymentOperationContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, deploymentOperationTimeout)
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

// failedDeploymentResultWithKind 构造带稳定失败类型的失败结果。
func failedDeploymentResultWithKind(message string, retryable bool, kind deployPB.FailureKind) *deployPB.DeploymentExecutionResult {
	result := failedDeploymentResult(message, retryable)
	result.FailureKind = kind
	return result
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
