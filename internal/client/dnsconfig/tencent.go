package dnsconfig

import (
	"context"
	"errors"
	"fmt"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	sdkerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	api "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
)

// tencentAPI 隔离云 SDK，测试不请求真实账户。
type tencentAPI interface {
	// DescribeDomainWithContext 校验域名访问。
	DescribeDomainWithContext(context.Context, *api.DescribeDomainRequest) (*api.DescribeDomainResponse, error)
	// DescribeRecordListWithContext 查询全部线路。
	DescribeRecordListWithContext(context.Context, *api.DescribeRecordListRequest) (*api.DescribeRecordListResponse, error)
	// CreateRecordWithContext 新增默认记录。
	CreateRecordWithContext(context.Context, *api.CreateRecordRequest) (*api.CreateRecordResponse, error)
}

// tencentBackend 独立使用 DNSPod 凭据，不依赖证书中心权限。
type tencentBackend struct {
	api tencentAPI // api 是 DNSPod SDK 客户端。
}

// newTencent 构造有硬超时的官方 DNSPod SDK。
func newTencent(p *config.Provider) (Backend, error) {
	profile := profile.NewClientProfile()
	profile.HttpProfile.ReqTimeout = 15
	client, err := api.NewClient(common.NewCredential(p.GetSecretId(), p.GetSecretKey()), "", profile)
	return &tencentBackend{client}, err
}

// FindZone 精确验证当前权威域名。
func (b *tencentBackend) FindZone(ctx context.Context, zone string) (string, error) {
	request := api.NewDescribeDomainRequest()
	request.Domain = new(zone)
	reply, err := b.api.DescribeDomainWithContext(ctx, request)
	if err != nil {
		return "", err
	}
	if reply == nil || reply.Response == nil || reply.Response.DomainInfo == nil || Normalize(ptrValue(reply.Response.DomainInfo.Domain)) != zone {
		return "", fmt.Errorf("DNS zone unavailable")
	}
	return zone, nil
}

// List 分页查询所有类型与线路，空目录错误仅按官方稳定错误码识别。
func (b *tencentBackend) List(ctx context.Context, zone string, r *deployPB.DnsRecord) ([]Entry, error) {
	var entries []Entry
	for offset := uint64(0); offset < 10000; offset += 100 {
		request := api.NewDescribeRecordListRequest()
		request.Domain = new(zone)
		request.Subdomain = new(r.Host)
		request.Offset = new(offset)
		request.Limit = new(uint64(100))
		reply, err := b.api.DescribeRecordListWithContext(ctx, request)
		if err != nil {
			var sdkErr *sdkerrors.TencentCloudSDKError
			if errors.As(err, &sdkErr) && sdkErr.GetCode() == "ResourceNotFound.NoDataOfRecord" {
				return entries, nil
			}
			return nil, err
		}
		if reply == nil || reply.Response == nil {
			return nil, fmt.Errorf("DNS response empty")
		}
		for _, record := range reply.Response.RecordList {
			if record == nil {
				return nil, fmt.Errorf("DNS record empty")
			}
			entries = append(entries, Entry{ptrValue(record.Name), ptrValue(record.Type), ptrValue(record.Value), ptrValue(record.Status) == "ENABLE", ptrValue(record.LineId) == "0"})
		}
		if len(reply.Response.RecordList) < 100 {
			return entries, nil
		}
	}
	return nil, fmt.Errorf("DNS pagination incomplete")
}

// Create 添加默认线路、启用状态的 CNAME。
func (b *tencentBackend) Create(ctx context.Context, zone string, r *deployPB.DnsRecord) (string, error) {
	request := api.NewCreateRecordRequest()
	request.Domain = new(zone)
	request.SubDomain = new(r.Host)
	request.RecordType = new("CNAME")
	request.RecordLine = new("默认")
	request.Value = new(r.Value)
	request.TTL = new(uint64(600))
	reply, err := b.api.CreateRecordWithContext(ctx, request)
	if reply != nil && reply.Response != nil {
		return ptrValue(reply.Response.RequestId), err
	}
	return "", err
}
