package dnsconfig

import (
	"context"
	"fmt"
	"strconv"

	"github.com/https-cert/deploy/internal/client/providers/aliyun"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// aliyunAPI 隔离签名传输，测试可模拟分页响应。
type aliyunAPI interface {
	// Call 复用固定端点的官方 OpenAPI 认证与响应解码。
	Call(context.Context, string, map[string]string) (map[string]any, string, error)
}

// aliyunBackend 通过固定 AliDNS 产品端点操作记录。
type aliyunBackend struct {
	api aliyunAPI // api 是最小 DNS RPC 接口。
}

// newAliyun 构建 DNS 专用客户端。
func newAliyun(p *config.Provider) (Backend, error) {
	api, err := aliyun.NewDNSCaller(p.GetAccessKeyId(), p.GetAccessKeySecret())
	return &aliyunBackend{api}, err
}

// FindZone 使用精确域名查询验证账户可访问当前权威区。
func (b *aliyunBackend) FindZone(ctx context.Context, zone string) (string, error) {
	body, _, err := b.api.Call(ctx, "DescribeDomainInfo", map[string]string{"DomainName": zone})
	if err != nil {
		return "", err
	}
	if Normalize(mapText(body, "DomainName")) != zone {
		return "", fmt.Errorf("DNS zone not accessible")
	}
	return zone, nil
}

// List 不按类型或线路筛选，完整读取所有同名记录。
func (b *aliyunBackend) List(ctx context.Context, zone string, r *deployPB.DnsRecord) ([]Entry, error) {
	var entries []Entry
	for page := 1; page <= 100; page++ {
		body, _, err := b.api.Call(ctx, "DescribeDomainRecords", map[string]string{"DomainName": zone, "RRKeyWord": r.Host, "SearchMode": "EXACT", "PageNumber": strconv.Itoa(page), "PageSize": "100"})
		if err != nil {
			return nil, err
		}
		container, ok := body["DomainRecords"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("DNS response invalid")
		}
		records, ok := container["Record"].([]any)
		if !ok {
			return nil, fmt.Errorf("DNS response invalid")
		}
		for _, item := range records {
			record, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("DNS response invalid")
			}
			entries = append(entries, Entry{mapText(record, "RR"), mapText(record, "Type"), mapText(record, "Value"), mapText(record, "Status") == "ENABLE", mapText(record, "Line") == "default"})
		}
		if len(records) < 100 {
			return entries, nil
		}
	}
	return nil, fmt.Errorf("DNS pagination incomplete")
}

// Create 新增默认线路的持久 CNAME。
func (b *aliyunBackend) Create(ctx context.Context, zone string, r *deployPB.DnsRecord) (string, error) {
	_, id, err := b.api.Call(ctx, "AddDomainRecord", map[string]string{"DomainName": zone, "RR": r.Host, "Type": "CNAME", "Value": r.Value, "TTL": "600", "Line": "default"})
	return id, err
}

// mapText 读取标准化 OpenAPI 响应的字符串字段。
func mapText(body map[string]any, key string) string {
	if value, ok := body[key].(string); ok {
		return value
	}
	return ""
}
