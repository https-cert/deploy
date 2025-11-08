package client

import (
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/orange-juzipi/cert-deploy/internal/client/providers"
	"github.com/orange-juzipi/cert-deploy/internal/client/providers/aliyun"
	"github.com/orange-juzipi/cert-deploy/internal/client/providers/qiniu"
	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/pb/deployPB"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
)

// executeBusines 执行业务
func (c *Client) executeBusines(stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse], requestId string, resp *deployPB.ExecuteBusinesResponse) {
	providerName := resp.Provider
	executeBusinesType := resp.ExecuteBusinesType
	domain := resp.Domain
	downloadURL := resp.Url
	cert := resp.Cert
	key := resp.Key

	// 上传证书备注
	remark := domain + "_" + time.Now().Format(time.DateTime)

	logger.Info("收到执行业务通知", "provider", providerName, "executeBusinesType", executeBusinesType, "domain", domain)

	var result deployPB.ExecuteBusinesRequest_RequestResult

	switch providerName {
	case "ansslCli":
		// ansslCli 是异步执行，不需要返回结果
		go c.deployCertificate(domain, downloadURL)
		return

	case "aliyun", "qiniu":
		result = c.handleCertificateProvider(providerName, executeBusinesType, remark, cert, key)

	default:
		result = deployPB.ExecuteBusinesRequest_REQUEST_RESULT_NOT_SUPPORTED
		logger.Warn("不支持的提供商", "provider", providerName)
	}

	// 发送执行业务响应给服务端
	c.sendExecuteBusinesResponse(stream, requestId, result)
}

// handleCertificateProvider 处理证书提供商的上传操作
func (c *Client) handleCertificateProvider(providerName string, executeBusinesType deployPB.ExecuteBusinesType, remark, cert, key string) deployPB.ExecuteBusinesRequest_RequestResult {
	// 只支持上传证书操作
	if executeBusinesType != deployPB.ExecuteBusinesType_EXECUTE_BUSINES_UPLOAD_CERT {
		return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_NOT_SUPPORTED
	}

	// 获取 provider 实例
	providerHandler, err := c.getProviderHandler(providerName)
	if err != nil {
		logger.Error("创建提供商实例失败", "provider", providerName, "error", err)
		return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
	}

	// 上传证书
	if err := providerHandler.UploadCertificate(remark, cert, key); err != nil {
		logger.Error("上传证书失败", "provider", providerName, "error", err)
		return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
	}

	logger.Info("证书上传成功", "provider", providerName, "remark", remark)
	return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_SUCCESS
}

// getProviderHandler 根据提供商名称获取对应的 handler
func (c *Client) getProviderHandler(providerName string) (providers.ProviderHandler, error) {
	providerConfig := config.GetProvider(providerName)
	if providerConfig == nil {
		return nil, fmt.Errorf("提供商配置不存在: %s", providerName)
	}

	switch providerName {
	case "aliyun":
		if providerConfig.AccessKeyId == "" || providerConfig.AccessKeySecret == "" {
			return nil, fmt.Errorf("阿里云配置不完整: accessKeyId 或 accessKeySecret 为空")
		}
		return aliyun.New(providerConfig.AccessKeyId, providerConfig.AccessKeySecret)

	case "qiniu":
		if providerConfig.AccessKey == "" || providerConfig.AccessSecret == "" {
			return nil, fmt.Errorf("七牛云配置不完整: accessKey 或 accessSecret 为空")
		}
		return qiniu.New(providerConfig.AccessKey, providerConfig.AccessSecret), nil

	default:
		return nil, fmt.Errorf("不支持的提供商: %s", providerName)
	}
}

// sendExecuteBusinesResponse 发送执行业务响应
func (c *Client) sendExecuteBusinesResponse(stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse], requestId string, result deployPB.ExecuteBusinesRequest_RequestResult) {
	req := &deployPB.ExecuteBusinesRequest{
		RequestResult: result,
	}

	if err := stream.Send(&deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientID,
		Version:   config.Version,
		RequestId: requestId,
		Data: &deployPB.NotifyRequest_ExecuteBusinesRequest{
			ExecuteBusinesRequest: req,
		},
	}); err != nil {
		logger.Error("发送执行业务响应给服务端失败", "error", err, "requestId", requestId)
	}
}

// deployCertificate 部署证书
func (c *Client) deployCertificate(domain, downloadURL string) {
	deployer := NewCertDeployer(c)
	if err := deployer.DeployCertificate(domain, downloadURL); err != nil {
		logger.Error("证书部署失败", "error", err, "domain", domain)
	}
}
