package client

import (
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/client/providers/aliyun"
	"github.com/https-cert/deploy/internal/client/providers/qiniu"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// executeBusines 执行业务
func (c *Client) executeBusines(stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse], requestId string, resp *deployPB.ExecuteBusinesResponse) {
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
		c.sendExecuteBusinesResponse(stream, requestId, deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED)
		return
	}

	// 上传证书备注
	remark := domain + "_" + time.Now().Format(time.DateTime)

	logger.Info("收到执行业务通知", "provider", providerName, "executeBusinesType", executeBusinesType, "domain", domain)

	var result deployPB.ExecuteBusinesRequest_RequestResult

	switch providerName {
	case "ansslCli":
		// 根据业务类型选择部署方式
		switch executeBusinesType {
		case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_CERT:
			// 部署证书到本地 nginx
			result = c.handleNginxCertificateDeploy(domain, downloadURL)
		case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_APACHE_CERT:
			// 部署证书到本地 apache
			result = c.handleApacheCertificateDeploy(domain, downloadURL)
		case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_RUSTFS_CERT:
			// 部署证书到本地 RustFS
			result = c.handleRustFSCertificateDeploy(domain, downloadURL)
		default:
			result = deployPB.ExecuteBusinesRequest_REQUEST_RESULT_NOT_SUPPORTED
			logger.Warn("不支持的业务类型", "executeBusinesType", executeBusinesType)
		}

	case "aliyun", "qiniu":
		result = c.handleCertificateProvider(providerName, executeBusinesType, remark, cert, key)

	default:
		result = deployPB.ExecuteBusinesRequest_REQUEST_RESULT_NOT_SUPPORTED
		logger.Warn("不支持的提供商", "provider", providerName)
	}

	// 发送执行业务响应给服务端
	c.sendExecuteBusinesResponse(stream, requestId, result)
}

// handleNginxCertificateDeploy 处理证书部署到本地 nginx
func (c *Client) handleNginxCertificateDeploy(domain, downloadURL string) deployPB.ExecuteBusinesRequest_RequestResult {
	if domain == "" {
		logger.Error("域名不能为空")
		return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
	}

	deployer := NewCertDeployer(c)
	if err := deployer.DeployCertificateToNginx(domain, downloadURL); err != nil {
		logger.Error("Nginx证书部署失败", "error", err, "domain", domain)
		return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
	}

	logger.Info("Nginx 证书部署成功", "domain", domain)
	return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_SUCCESS
}

// handleApacheCertificateDeploy 处理证书部署到本地 apache
func (c *Client) handleApacheCertificateDeploy(domain, downloadURL string) deployPB.ExecuteBusinesRequest_RequestResult {
	if domain == "" {
		logger.Error("域名不能为空")
		return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
	}

	deployer := NewCertDeployer(c)
	if err := deployer.DeployCertificateToApache(domain, downloadURL); err != nil {
		logger.Error("Apache证书部署失败", "error", err, "domain", domain)
		return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
	}

	logger.Info("Apache 证书部署成功", "domain", domain)
	return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_SUCCESS
}

// handleRustFSCertificateDeploy 处理证书部署到本地 RustFS
func (c *Client) handleRustFSCertificateDeploy(domain, downloadURL string) deployPB.ExecuteBusinesRequest_RequestResult {
	if domain == "" {
		logger.Error("域名不能为空")
		return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
	}

	deployer := NewCertDeployer(c)
	if err := deployer.DeployCertificateToRustFS(domain, downloadURL); err != nil {
		logger.Error("RustFS证书部署失败", "error", err, "domain", domain)
		return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_FAILED
	}

	logger.Info("RustFS 证书部署成功", "domain", domain)
	return deployPB.ExecuteBusinesRequest_REQUEST_RESULT_SUCCESS
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
		accessKeyId := providerConfig.GetAccessKeyId()
		accessKeySecret := providerConfig.GetAccessKeySecret()
		if accessKeyId == "" || accessKeySecret == "" {
			return nil, fmt.Errorf("阿里云配置不完整: accessKeyId 或 accessKeySecret 为空")
		}
		return aliyun.New(accessKeyId, accessKeySecret)

	case "qiniu":
		accessKey := providerConfig.GetAccessKey()
		accessSecret := providerConfig.GetAccessSecret()
		if accessKey == "" || accessSecret == "" {
			return nil, fmt.Errorf("七牛云配置不完整: accessKey 或 accessSecret 为空")
		}
		return qiniu.New(accessKey, accessSecret), nil

	default:
		return nil, fmt.Errorf("不支持的提供商: %s", providerName)
	}
}

// sendExecuteBusinesResponse 发送执行业务响应
func (c *Client) sendExecuteBusinesResponse(stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse], requestId string, result deployPB.ExecuteBusinesRequest_RequestResult) {
	req := &deployPB.ExecuteBusinesRequest{
		RequestResult: result,
	}

	// 使用传入的 stream 发送
	if err := stream.Send(&deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientId,
		Version:   config.Version,
		RequestId: requestId,
		Data: &deployPB.NotifyRequest_ExecuteBusinesRequest{
			ExecuteBusinesRequest: req,
		},
	}); err != nil {
		logger.Error("发送执行业务响应失败", "error", err, "requestId", requestId)
	}
}
