package dnsconfig

import (
	"context"
	"fmt"

	"github.com/baidubce/bce-sdk-go/bce"
	api "github.com/baidubce/bce-sdk-go/services/dns"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// baiduAPI 隔离云 SDK，测试不请求真实账户。
type baiduAPI interface {
	// ListZone 分页读取托管区。
	ListZone(*api.ListZoneRequest) (*api.ListZoneResponse, error)
	// ListRecord 读取所有记录线路。
	ListRecord(string, *api.ListRecordRequest) (*api.ListRecordResponse, error)
	// CreateRecord 新增解析。
	CreateRecord(string, *api.CreateRecordRequest, string) (string, error)
}

// baiduSDK 保留官方签名和序列化，仅补回 SDK 高层方法丢弃的请求 ID。
type baiduSDK struct {
	*api.Client // Client 负责官方 DNS 查询与认证。
}

// baiduResponseClient 为单次新增捕获响应元信息，避免与后续回读混淆。
type baiduResponseClient struct {
	bce.Client        // Client 复用官方请求发送器。
	requestID  string // requestID 是本次新增的云端请求标识。
}

// SendRequest 沿用官方请求流程，仅记录脱敏请求标识。
func (c *baiduResponseClient) SendRequest(request *bce.BceRequest, response *bce.BceResponse) error {
	err := c.Client.SendRequest(request, response)
	c.requestID = response.RequestId()
	return err
}

// CreateRecord 使用官方 API 函数发起新增并保留响应头请求 ID。
func (c *baiduSDK) CreateRecord(zone string, request *api.CreateRecordRequest, token string) (string, error) {
	sender := &baiduResponseClient{Client: c.Client}
	err := api.CreateRecord(sender, zone, request, token)
	return sender.requestID, err
}

// baiduBackend 使用现有百度 SDK 的公网 DNS 产品。
type baiduBackend struct {
	api baiduAPI // api 是 DNS 客户端。
}

// newBaidu 构造带硬超时的 DNS 客户端。
func newBaidu(p *config.Provider) (Backend, error) {
	client, err := api.NewClient(p.GetAccessKeyId(), p.GetAccessKeySecret(), "https://dns.baidubce.com")
	if err == nil {
		client.Config.ConnectionTimeoutInMillis = 15000
		client.Config.Retry = bce.NewNoRetryPolicy()
	}
	return &baiduBackend{&baiduSDK{Client: client}}, err
}

// FindZone 按 marker 分页精确匹配权威区。
func (b *baiduBackend) FindZone(ctx context.Context, zone string) (string, error) {
	marker := ""
	for page := 0; page < 100; page++ {
		if err := contextCheck(ctx); err != nil {
			return "", err
		}
		reply, err := b.api.ListZone(&api.ListZoneRequest{Name: zone, Marker: marker, MaxKeys: 100})
		if err != nil {
			return "", err
		}
		if reply == nil {
			return "", fmt.Errorf("DNS response empty")
		}
		for _, item := range reply.Zones {
			if Normalize(item.Name) == zone {
				return zone, nil
			}
		}
		if !reply.IsTruncated {
			return "", fmt.Errorf("DNS zone inaccessible")
		}
		if reply.NextMarker == "" || reply.NextMarker == marker {
			return "", fmt.Errorf("DNS pagination invalid")
		}
		marker = reply.NextMarker
	}
	return "", fmt.Errorf("DNS pagination incomplete")
}

// List 遍历全部记录线路，过滤在统一冲突判定中完成。
func (b *baiduBackend) List(ctx context.Context, zone string, r *deployPB.DnsRecord) ([]Entry, error) {
	var entries []Entry
	marker := ""
	for page := 0; page < 100; page++ {
		if err := contextCheck(ctx); err != nil {
			return nil, err
		}
		reply, err := b.api.ListRecord(zone, &api.ListRecordRequest{Rr: r.Host, Marker: marker, MaxKeys: 100})
		if err != nil {
			return nil, err
		}
		if reply == nil {
			return nil, fmt.Errorf("DNS response empty")
		}
		for _, item := range reply.Records {
			entries = append(entries, Entry{item.Rr, item.Type, item.Value, item.Status == "enable", (item.Line == "" || item.Line == "default")})
		}
		if !reply.IsTruncated {
			return entries, ctx.Err()
		}
		if reply.NextMarker == "" || reply.NextMarker == marker {
			return nil, fmt.Errorf("DNS pagination invalid")
		}
		marker = reply.NextMarker
	}
	return nil, fmt.Errorf("DNS pagination incomplete")
}

// Create 以快照摘要作为百度 API 幂等 token。
func (b *baiduBackend) Create(ctx context.Context, zone string, r *deployPB.DnsRecord) (string, error) {
	if err := contextCheck(ctx); err != nil {
		return "", err
	}
	return b.api.CreateRecord(zone, &api.CreateRecordRequest{Rr: r.Host, Type: "CNAME", Value: r.Value, Ttl: new(int32(600))}, r.Fingerprint)
}
