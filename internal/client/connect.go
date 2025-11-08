package client

import (
	"connectrpc.com/connect"
	"github.com/orange-juzipi/cert-deploy/internal/client/providers/aliyun"
	"github.com/orange-juzipi/cert-deploy/internal/client/providers/qiniu"
	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/pb/deployPB"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
)

// handleConnect 处理测试连接
func (c *Client) handleConnect(stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse], requestId string, data *deployPB.ConnectRequest) error {
	logger.Info("收到【测试连接提供商】请求", "provider", data.Provider, "requestId", requestId)

	success := false
	var err error

	switch data.Provider {
	case "ansslCli":
		success = true
	case "aliyun":
		providerConfig := config.GetProvider("aliyun")
		provider, err := aliyun.New(providerConfig.AccessKeyId, providerConfig.AccessKeySecret)
		if err != nil {
			return err
		}
		success, err = provider.TestConnection()
		if err != nil {
			return err
		}

	case "cloudTencent":
		success = false

	case "qiniu":
		providerConfig := config.GetProvider("qiniu")
		provider := qiniu.New(providerConfig.AccessKey, providerConfig.AccessSecret)

		success, err = provider.TestConnection()
		if err != nil {
			return err
		}

	default:
		logger.Warn("未知提供商", "provider", data.Provider)
		success = false
	}

	// 发送响应给服务端
	if err := stream.Send(&deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientID,
		Version:   config.Version,
		RequestId: requestId,
		Data: &deployPB.NotifyRequest_ConnectRequest{
			ConnectRequest: &deployPB.ConnectRequest{
				Provider: data.Provider,
				Success:  success,
			},
		},
	}); err != nil {
		return err
	}

	return nil
}
