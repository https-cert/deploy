package dnsconfig

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	api "github.com/volcengine/volcengine-go-sdk/service/dns"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

// volcAPI 隔离云 SDK，测试不请求真实账户。
type volcAPI interface {
	// ListZonesWithContext 分页读取托管区。
	ListZonesWithContext(volcengine.Context, *api.ListZonesInput, ...request.Option) (*api.ListZonesOutput, error)
	// ListRecordsWithContext 查询所有线路。
	ListRecordsWithContext(volcengine.Context, *api.ListRecordsInput, ...request.Option) (*api.ListRecordsOutput, error)
	// CreateRecordWithContext 新增默认记录。
	CreateRecordWithContext(volcengine.Context, *api.CreateRecordInput, ...request.Option) (*api.CreateRecordOutput, error)
}

// volcBackend 使用火山引擎 DNS 产品客户端。
type volcBackend struct {
	api volcAPI // api 是上下文感知 SDK。
}

// newVolc 使用全球 DNS 产品默认签名地域，并保留用户配置。
func newVolc(p *config.Provider) (Backend, error) {
	region := p.Region
	if region == "" {
		region = "cn-beijing"
	}
	s, err := session.NewSession(volcengine.NewConfig().WithRegion(region).WithCredentials(credentials.NewStaticCredentials(p.GetAccessKeyId(), p.GetAccessKeySecret(), "")).WithHTTPClient(&http.Client{Timeout: 15 * time.Second}))
	if err != nil {
		return nil, err
	}
	return &volcBackend{api.New(s)}, nil
}

// FindZone 分页精确查找最近权威区。
func (b *volcBackend) FindZone(ctx context.Context, zone string) (string, error) {
	for page := int32(1); page <= 100; page++ {
		reply, err := b.api.ListZonesWithContext(ctx, &api.ListZonesInput{Key: new(zone), PageNumber: new(page), PageSize: new(int32(100))})
		if err != nil {
			return "", err
		}
		if reply == nil {
			return "", fmt.Errorf("DNS response empty")
		}
		for _, item := range reply.Zones {
			if item != nil && Normalize(ptrValue(item.ZoneName)) == zone {
				return strconv.Itoa(int(ptrValue(item.ZID))), nil
			}
		}
		if len(reply.Zones) < 100 {
			return "", fmt.Errorf("DNS zone inaccessible")
		}
	}
	return "", fmt.Errorf("DNS pagination incomplete")
}

// List 分页查询全部类型、线路及停用记录。
func (b *volcBackend) List(ctx context.Context, zone string, r *deployPB.DnsRecord) ([]Entry, error) {
	id, err := strconv.ParseInt(zone, 10, 64)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for page := int32(1); page <= 100; page++ {
		reply, err := b.api.ListRecordsWithContext(ctx, &api.ListRecordsInput{ZID: new(id), Host: new(r.Host), PageNumber: new(page), PageSize: new(int32(100))})
		if err != nil {
			return nil, err
		}
		if reply == nil {
			return nil, fmt.Errorf("DNS response empty")
		}
		for _, item := range reply.Records {
			if item == nil {
				return nil, fmt.Errorf("DNS response invalid")
			}
			entries = append(entries, Entry{ptrValue(item.Host), ptrValue(item.Type), ptrValue(item.Value), ptrValue(item.Enable), ptrValue(item.Line) == "default"})
		}
		if len(reply.Records) < 100 {
			return entries, nil
		}
	}
	return nil, fmt.Errorf("DNS pagination incomplete")
}

// Create 新增启用的默认线路 CNAME。
func (b *volcBackend) Create(ctx context.Context, zone string, r *deployPB.DnsRecord) (string, error) {
	id, err := strconv.ParseInt(zone, 10, 64)
	if err != nil {
		return "", err
	}
	reply, err := b.api.CreateRecordWithContext(ctx, &api.CreateRecordInput{ZID: new(id), Host: new(r.Host), Type: new("CNAME"), Value: new(r.Value), Line: new("default"), TTL: new(int32(600))})
	if reply != nil && reply.Metadata != nil {
		return reply.Metadata.RequestId, err
	}
	return "", err
}
