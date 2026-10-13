package dnsconfig

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/jdcloud-api/jdcloud-sdk-go/core"
	api "github.com/jdcloud-api/jdcloud-sdk-go/services/domainservice/apis"
	client "github.com/jdcloud-api/jdcloud-sdk-go/services/domainservice/client"
	model "github.com/jdcloud-api/jdcloud-sdk-go/services/domainservice/models"
)

// jdAPI 隔离云 SDK，测试不请求真实账户。
type jdAPI interface {
	// DescribeDomains 读取域名分页。
	DescribeDomains(*api.DescribeDomainsRequest) (*api.DescribeDomainsResponse, error)
	// DescribeResourceRecord 查询全部线路。
	DescribeResourceRecord(*api.DescribeResourceRecordRequest) (*api.DescribeResourceRecordResponse, error)
	// CreateResourceRecord 新增记录。
	CreateResourceRecord(*api.CreateResourceRecordRequest) (*api.CreateResourceRecordResponse, error)
}

// jdBackend 保存 DNS 专属 SDK 与地域。
type jdBackend struct {
	api    jdAPI  // api 是官方 Domainservice 客户端。
	region string // region 是请求地域。
}

// newJD 构造 DNS 客户端并禁用 SDK 日志，避免打印凭据。
func newJD(p *config.Provider) (Backend, error) {
	client := client.NewDomainserviceClient(core.NewCredentials(p.GetAccessKeyId(), p.GetAccessKeySecret()))
	client.DisableLogger()
	client.Config.SetTimeout(15 * time.Second)
	region := p.Region
	if region == "" {
		region = "cn-north-1"
	}
	return &jdBackend{client, region}, nil
}

// FindZone 分页读取精确域名 ID。
func (b *jdBackend) FindZone(ctx context.Context, zone string) (string, error) {
	for page := 1; page <= 100; page++ {
		if err := contextCheck(ctx); err != nil {
			return "", err
		}
		request := api.NewDescribeDomainsRequestWithoutParam()
		request.SetRegionId(b.region)
		request.SetPageNumber(page)
		request.SetPageSize(100)
		request.SetDomainName(zone)
		reply, err := b.api.DescribeDomains(request)
		if err != nil {
			return "", err
		}
		if reply == nil {
			return "", fmt.Errorf("DNS response empty")
		}
		if reply.Error.Code != 0 {
			return "", fmt.Errorf("DNS API error %d: %s", reply.Error.Code, reply.Error.Status)
		}
		for _, item := range reply.Result.DataList {
			if Normalize(item.DomainName) == zone {
				return strconv.Itoa(item.Id), nil
			}
		}
		if page >= reply.Result.TotalPage {
			return "", fmt.Errorf("DNS zone inaccessible")
		}
	}
	return "", fmt.Errorf("DNS pagination incomplete")
}

// List 查询全部同名解析与线路，拒绝不完整分页。
func (b *jdBackend) List(ctx context.Context, zone string, r *deployPB.DnsRecord) ([]Entry, error) {
	var entries []Entry
	for page := 1; page <= 100; page++ {
		if err := contextCheck(ctx); err != nil {
			return nil, err
		}
		request := api.NewDescribeResourceRecordRequest(b.region, zone)
		request.SetPageNumber(page)
		request.SetPageSize(100)
		request.SetSearch(r.Host)
		reply, err := b.api.DescribeResourceRecord(request)
		if err != nil {
			return nil, err
		}
		if reply == nil {
			return nil, fmt.Errorf("DNS response empty")
		}
		if reply.Error.Code != 0 {
			return nil, fmt.Errorf("DNS API error %d: %s", reply.Error.Code, reply.Error.Status)
		}
		for _, item := range reply.Result.DataList {
			defaultLine := len(item.ViewValue) == 1 && item.ViewValue[0] == -1
			entries = append(entries, Entry{item.HostRecord, item.Type, item.HostValue, item.ResolvingStatus == "2", defaultLine})
		}
		if page >= reply.Result.TotalPage {
			return entries, ctx.Err()
		}
	}
	return nil, fmt.Errorf("DNS pagination incomplete")
}

// Create 新增默认线路，保留响应中的云请求 ID。
func (b *jdBackend) Create(ctx context.Context, zone string, r *deployPB.DnsRecord) (string, error) {
	if err := contextCheck(ctx); err != nil {
		return "", err
	}
	request := api.NewCreateResourceRecordRequest(b.region, zone, &model.AddRR{HostRecord: r.Host, HostValue: r.Value, Ttl: 600, Type: "CNAME", ViewValue: -1})
	reply, err := b.api.CreateResourceRecord(request)
	if err != nil {
		return "", err
	}
	if reply == nil {
		return "", fmt.Errorf("DNS response empty")
	}
	if reply.Error.Code != 0 {
		return reply.RequestID, fmt.Errorf("DNS API error %d: %s", reply.Error.Code, reply.Error.Status)
	}
	return reply.RequestID, nil
}
