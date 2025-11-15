package client

import (
	"connectrpc.com/connect"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// handleGetProvider 处理获取提供商信息请求
func (c *Client) handleGetProvider(stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse], requestID string) {
	logger.Info("收到【获取提供商信息】请求", "requestID", requestID)

	cfg := config.GetConfig()

	var providers []*deployPB.GetProviderResponse_Provider
	for _, p := range cfg.Provider {
		providers = append(providers, &deployPB.GetProviderResponse_Provider{
			Name:   p.Name,
			Remark: p.Remark,
		})
	}

	err := stream.Send(&deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientID,
		RequestId: requestID,
		Data: &deployPB.NotifyRequest_GetProviderResponse{
			GetProviderResponse: &deployPB.GetProviderResponse{
				Providers: providers,
			},
		},
	})
	if err != nil {
		logger.Error("发送【获取提供商信息】响应失败", "error", err, "requestID", requestID)
		return
	}
}
