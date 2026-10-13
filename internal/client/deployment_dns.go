package client

import (
	"context"

	"github.com/https-cert/deploy/internal/client/dnsconfig"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// runDNS 将 DNS 操作纳入并发槽和 55 秒响应时限；不可取消 SDK 仍持有记录锁直到收敛。
func (s *deploymentService) runDNS(requestID string, request *deployPB.DnsOperationRequest, write bool) {
	name := "dns-check"
	if write {
		name = "dns-configure"
	}
	record := request.GetRecord()
	s.ops.Run(name, func() {
		s.sendDNSResult(requestID, &deployPB.DnsOperationResult{Record: record, Status: deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_FAILED, Message: "客户端繁忙，请稍后重试"}, write)
	}, func() {
		ctx, cancel := newDeploymentOperationContext(s.parent)
		defer cancel()
		// 百度、京东和部分华为 SDK 不支持 context，中途超时仍不能提前释放串行锁。
		completed := make(chan *deployPB.DnsOperationResult, 1)
		go func() { completed <- s.performDNS(ctx, record, write) }()
		select {
		case result := <-completed:
			logger.Info("DNS 操作完成", "operation", name, "requestId", requestID, "provider", record.GetProvider().String(), "status", result.Status.String())
			s.sendDNSResult(requestID, result, write)
		case <-ctx.Done():
			status := deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_FAILED
			if write {
				status = deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_UNCONFIRMED
			}
			s.sendDNSResult(requestID, &deployPB.DnsOperationResult{Record: record, Status: status, Message: "客户端操作超时，结果待确认，请重新检查远端记录"}, write)
			// 响应只发送一次，但业务槽位保持占用，避免未收敛的 SDK 调用持续累积。
			<-completed
		}
	})
}

// performDNS 获取同区同名串行锁后复查远端状态，完成或取消时释放锁。
func (s *deploymentService) performDNS(ctx context.Context, record *deployPB.DnsRecord, write bool) *deployPB.DnsOperationResult {
	if record == nil {
		return &deployPB.DnsOperationResult{Status: deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_FAILED, Message: "DNS 记录不能为空"}
	}
	release, err := s.client.lockOperationWithContext(ctx, "dns\x00"+dnsconfig.Normalize(record.Zone)+"\x00"+dnsconfig.Normalize(record.Fqdn))
	if err != nil {
		return &deployPB.DnsOperationResult{Record: record, Status: deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_FAILED, Message: "等待 DNS 记录锁超时，请重试"}
	}
	defer release()
	factory := s.newDNSBackend
	if factory == nil {
		factory = dnsconfig.NewBackend
	}
	backend, err := factory(s.client.runtime, record.Provider)
	if err != nil {
		return &deployPB.DnsOperationResult{Record: record, Status: deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_NOT_CONFIGURED, Message: "CLI DNS 密钥未配置或初始化失败"}
	}
	return dnsconfig.Operate(ctx, backend, record, write)
}

// sendDNSResult 按请求类型回包，密钥和 SDK 原始错误不进入信封。
func (s *deploymentService) sendDNSResult(requestID string, result *deployPB.DnsOperationResult, write bool) {
	envelope := &deployPB.DeploymentRequest{AccessKey: s.accessKey, ClientId: s.clientID, RequestId: requestID}
	if write {
		envelope.Data = &deployPB.DeploymentRequest_DnsConfigureResponse{DnsConfigureResponse: result}
	} else {
		envelope.Data = &deployPB.DeploymentRequest_DnsCheckResponse{DnsCheckResponse: result}
	}
	if s.sendEnvelope == nil {
		logger.Warn("DNS 响应发送器未初始化")
		return
	}
	s.sendEnvelope(envelope)
}
