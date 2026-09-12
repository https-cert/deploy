package client

import (
	"context"
	"errors"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// deploymentService 处理 v2 业务消息分发、执行与回包组装。
type deploymentService struct {
	client       *WSClient
	handlers     *DeploymentHandlerRegistry
	executor     *DeploymentExecutor
	ops          *operationRunner
	accessKey    string
	clientID     string
	parent       context.Context
	sendEnvelope func(*deployPB.DeploymentRequest)
}

func newDeploymentService(client *WSClient) *deploymentService {
	return &deploymentService{
		client:       client,
		handlers:     client.deploymentHandlers,
		executor:     client.deploymentExecutor,
		ops:          client.ops,
		accessKey:    client.accessKey,
		clientID:     client.clientId,
		parent:       client.ctx,
		sendEnvelope: client.sendDeploymentEnvelope,
	}
}

// HandleResponse 分发服务端下发的 v2 部署请求。
func (s *deploymentService) HandleResponse(response *deployPB.DeploymentResponse) {
	if response == nil {
		return
	}
	switch data := response.GetData().(type) {
	case *deployPB.DeploymentResponse_Register:
		if s.client.registrationLogged.CompareAndSwap(false, true) {
			logger.Info("deployment v2 注册成功", "protocolVersion", data.Register.GetProtocolVersion(), "clientVersion", data.Register.GetClientVersion())
		}
	case *deployPB.DeploymentResponse_DiscoverRequest:
		requestID := response.GetRequestId()
		s.ops.Run("deployment-v2-discover", func() {
			s.sendDiscoverResponse(requestID, unavailableDeploymentCapability(data.DiscoverRequest.GetSelector()))
		}, func() {
			s.handleDiscoverRequest(requestID, data.DiscoverRequest)
		})
	case *deployPB.DeploymentResponse_TestRequest:
		requestID := deploymentRequestID(response.GetRequestId(), data.TestRequest.GetRequestId())
		s.ops.Run("deployment-v2-test", func() {
			s.sendTestResponse(requestID, data.TestRequest.GetSelector(), failedDeploymentResultWithKind("客户端业务并发已达上限", true, deployPB.FailureKind_FAILURE_KIND_BUSY))
		}, func() {
			s.handleTestRequest(requestID, data.TestRequest)
		})
	case *deployPB.DeploymentResponse_ExecuteRequest:
		requestID := deploymentRequestID(response.GetRequestId(), data.ExecuteRequest.GetRequestId())
		s.ops.Run("deployment-v2-execute", func() {
			s.sendExecuteResponse(requestID, data.ExecuteRequest.GetSelector(), failedDeploymentResultWithKind("客户端业务并发已达上限", true, deployPB.FailureKind_FAILURE_KIND_BUSY))
		}, func() {
			s.handleExecuteRequest(requestID, data.ExecuteRequest)
		})
	case *deployPB.DeploymentResponse_ChallengeRequest:
		requestID := deploymentRequestID(response.GetRequestId(), data.ChallengeRequest.GetRequestId())
		s.ops.Run("deployment-v2-challenge", func() {
			s.sendChallengeResponse(requestID, data.ChallengeRequest, failedDeploymentResultWithKind("客户端业务并发已达上限", true, deployPB.FailureKind_FAILURE_KIND_BUSY))
		}, func() {
			s.handleChallengeRequest(requestID, data.ChallengeRequest)
		})
	case *deployPB.DeploymentResponse_UpdateRequest:
		s.ops.Run("deployment-v2-update", nil, func() {
			s.handleUpdateRequest(data.UpdateRequest)
		})
	default:
		logger.Warn("忽略未知 deployment v2 消息", "requestId", response.GetRequestId())
	}
}

func (s *deploymentService) handleUpdateRequest(request *deployPB.DeploymentUpdateRequest) {
	if request == nil {
		logger.Warn("忽略空的 deployment v2 更新请求")
		return
	}
	logger.Info("收到 deployment v2 更新请求", "version", request.GetVersion())
	updateHandler := NewUpdateHandler(s.parent, s.client.runtime)
	updateHandler.HandleUpdate()
}

func (s *deploymentService) handleDiscoverRequest(requestID string, request *deployPB.DeploymentDiscoverRequest) {
	selector := request.GetSelector()
	handler, ok := s.lookup(selector)
	if !ok {
		s.sendDiscoverResponse(requestID, unavailableDeploymentCapability(selector))
		return
	}
	capability := handler.Capability()
	if request.GetIncludeResources() {
		operationCtx, cancel := newDeploymentOperationContext(s.parent)
		defer cancel()
		catalog := handler.DiscoverResources(operationCtx)
		if catalog.Error != nil {
			logger.ErrorLocal("deployment v2 资源发现失败", "error", catalog.Error, "provider", selector.GetProvider().String(), "deploymentType", selector.GetDeploymentType().String(), "requestId", requestID)
		}
		capability.ResourceStatus = catalog.Status
		capability.Resources = deploymentResourcesFromProvider(catalog.Resources)
	}
	s.sendDiscoverResponse(requestID, capability)
}

func (s *deploymentService) handleTestRequest(requestID string, request *deployPB.DeploymentTestRequest) {
	selector := request.GetSelector()
	handler, ok := s.lookup(selector)
	if !ok {
		s.sendTestResponse(requestID, selector, unsupportedDeploymentResult("客户端不支持该部署能力"))
		return
	}
	operationCtx, cancel := newDeploymentOperationContext(s.parent)
	defer cancel()
	if err := handler.Test(operationCtx, selector.GetTargetRef()); err != nil {
		message, retryable := providers.DeploymentErrorInfo(err)
		logger.ErrorLocal("deployment v2 目标测试失败", "error", err, "provider", selector.GetProvider().String(), "deploymentType", selector.GetDeploymentType().String(), "requestId", requestID)
		result := failedDeploymentResult(message, retryable)
		result.ProviderRequestId = providerRequestID(err)
		result.FailureKind = providers.FailureKind(err)
		s.sendTestResponse(requestID, selector, result)
		return
	}
	s.sendTestResponse(requestID, selector, successfulDeploymentResult("目标测试成功", ""))
}

func (s *deploymentService) handleExecuteRequest(requestID string, request *deployPB.DeploymentExecuteRequest) {
	selector := request.GetSelector()
	handler, ok := s.lookup(selector)
	if !ok {
		s.sendExecuteResponse(requestID, selector, unsupportedDeploymentResult("客户端不支持该部署能力"))
		return
	}
	s.ops.AddBusy(1)
	defer s.ops.AddBusy(-1)
	operationCtx, cancel := newDeploymentOperationContext(s.parent)
	defer cancel()
	result, err := handler.Deploy(operationCtx, DeploymentHandlerRequest{
		RequestID:      requestID,
		TargetRef:      selector.GetTargetRef(),
		Domain:         request.GetDomain(),
		DownloadURL:    request.GetUrl(),
		CertificatePEM: request.GetCert(),
		PrivateKeyPEM:  request.GetKey(),
	})
	if err != nil {
		if isClientContextCanceled(err, s.parent) {
			return
		}
		message, retryable := providers.DeploymentErrorInfo(err)
		executionResult := failedDeploymentResult(message, retryable)
		executionResult.ProviderRequestId = providerRequestID(err)
		executionResult.FailureKind = providers.FailureKind(err)
		s.sendExecuteResponse(requestID, selector, executionResult)
		return
	}
	if err := operationCtx.Err(); err != nil {
		if isClientContextCanceled(err, s.parent) {
			return
		}
		message, retryable := providers.DeploymentErrorInfo(err)
		executionResult := failedDeploymentResultWithKind(message, retryable, providers.FailureKind(err))
		s.sendExecuteResponse(requestID, selector, executionResult)
		return
	}
	s.sendExecuteResponse(requestID, selector, successfulDeploymentResult(result.Message, result.RequestID))
}

func (s *deploymentService) handleChallengeRequest(requestID string, request *deployPB.DeploymentChallengeRequest) {
	s.sendChallengeResponse(requestID, request, s.executeChallenge(request))
}

func (s *deploymentService) executeChallenge(request *deployPB.DeploymentChallengeRequest) *deployPB.DeploymentExecutionResult {
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
	if s.client == nil || s.client.httpServer == nil {
		return failedDeploymentResult("HTTP-01 服务未初始化", false)
	}
	httpServer := s.client.httpServer
	switch request.GetAction() {
	case deployPB.DeploymentChallengeRequest_ACTION_SET:
		if err := httpServer.SetChallenge(request.GetToken(), request.GetKeyAuth(), canonicalDomain); err != nil {
			logger.ErrorLocal("设置 HTTP-01 Challenge 失败", "error", err, "operationId", request.GetOperationId(), "certId", request.GetCertId(), "domain", canonicalDomain)
			return failedDeploymentResult("HTTP-01 设置失败，请查看 deploy 客户端日志", false)
		}
		logger.Info("设置 HTTP-01 Challenge", "operationId", request.GetOperationId(), "certId", request.GetCertId(), "token", request.GetToken(), "domain", canonicalDomain)
		return successfulDeploymentResult("HTTP-01 challenge 已缓存", "")
	case deployPB.DeploymentChallengeRequest_ACTION_DELETE:
		if err := httpServer.RemoveChallenge(request.GetToken()); err != nil {
			logger.ErrorLocal("删除 HTTP-01 Challenge 失败", "error", err, "operationId", request.GetOperationId(), "certId", request.GetCertId(), "domain", canonicalDomain)
			return failedDeploymentResult("HTTP-01 清理失败，请查看 deploy 客户端日志", false)
		}
		logger.Info("删除 HTTP-01 Challenge", "operationId", request.GetOperationId(), "certId", request.GetCertId(), "token", request.GetToken(), "domain", canonicalDomain)
		return successfulDeploymentResult("HTTP-01 challenge 已删除", "")
	default:
		return unsupportedDeploymentResult("不支持的 HTTP-01 操作")
	}
}

func (s *deploymentService) lookup(selector *deployPB.DeploymentSelector) (DeploymentHandler, bool) {
	if selector == nil || s.handlers == nil {
		return nil, false
	}
	return s.handlers.Lookup(selector.GetProvider(), selector.GetDeploymentType())
}

func (s *deploymentService) sendDiscoverResponse(requestID string, capability *deployPB.DeploymentCapability) {
	s.sendEnvelope(&deployPB.DeploymentRequest{AccessKey: s.accessKey, ClientId: s.clientID, RequestId: requestID, Data: &deployPB.DeploymentRequest_DiscoverResponse{DiscoverResponse: &deployPB.DeploymentDiscoverResponse{Capability: capability}}})
}

func (s *deploymentService) sendTestResponse(requestID string, selector *deployPB.DeploymentSelector, result *deployPB.DeploymentExecutionResult) {
	s.sendEnvelope(&deployPB.DeploymentRequest{AccessKey: s.accessKey, ClientId: s.clientID, RequestId: requestID, Data: &deployPB.DeploymentRequest_TestResponse{TestResponse: &deployPB.DeploymentTestResponse{RequestId: requestID, Selector: selector, Result: result}}})
}

func (s *deploymentService) sendExecuteResponse(requestID string, selector *deployPB.DeploymentSelector, result *deployPB.DeploymentExecutionResult) {
	s.sendEnvelope(&deployPB.DeploymentRequest{AccessKey: s.accessKey, ClientId: s.clientID, RequestId: requestID, Data: &deployPB.DeploymentRequest_ExecuteResponse{ExecuteResponse: &deployPB.DeploymentExecuteResponse{RequestId: requestID, Selector: selector, Result: result}}})
}

func (s *deploymentService) sendChallengeResponse(requestID string, request *deployPB.DeploymentChallengeRequest, result *deployPB.DeploymentExecutionResult) {
	response := &deployPB.DeploymentChallengeResponse{RequestId: requestID, Result: result}
	if request != nil {
		response.OperationId = request.GetOperationId()
		response.CertId = request.GetCertId()
		response.Domain = request.GetDomain()
		response.Token = request.GetToken()
	}
	s.sendEnvelope(&deployPB.DeploymentRequest{AccessKey: s.accessKey, ClientId: s.clientID, RequestId: requestID, Data: &deployPB.DeploymentRequest_ChallengeResponse{ChallengeResponse: response}})
}

func isClientContextCanceled(err error, parent context.Context) bool {
	return errors.Is(err, context.Canceled) && parent != nil && parent.Err() != nil
}
