package dnsconfig

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	cfdns "github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	cfzones "github.com/cloudflare/cloudflare-go/v7/zones"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

const (
	cloudflareZonePageSize   = 50
	cloudflareRecordPageSize = 100
	cloudflareMaxPages       = 100
	cloudflareAPIBaseURL     = "https://api.cloudflare.com/client/v4"
)

// cloudflareAPI 封装 Cloudflare DNS 与 Zone API 的单页请求。
type cloudflareAPI interface {
	// ListZones 按域名获取一页 Zone。
	ListZones(context.Context, string, int64) ([]cfzones.Zone, error)
	// ListRecords 查询指定完整记录名的一页全部类型记录。
	ListRecords(context.Context, string, string, int64) ([]cfdns.RecordResponse, error)
	// CreateRecord 创建不代理的 CNAME 并返回 Cloudflare 请求标识。
	CreateRecord(context.Context, string, *deployPB.DnsRecord) (string, error)
}

// cloudflareSDK 通过官方 SDK 调用 Cloudflare API。
type cloudflareSDK struct {
	client *cloudflare.Client // client 使用本机 API Token 授权。
}

// newCloudflare 创建只使用 DNS API Token 的适配器。
func newCloudflare(p *config.Provider) (Backend, error) {
	token := strings.TrimSpace(p.GetAPIToken())
	if token == "" {
		return nil, fmt.Errorf("Cloudflare API Token 未配置")
	}
	client := cloudflare.NewClient(
		option.WithAPIToken(token),
		option.WithBaseURL(cloudflareAPIBaseURL),
		option.WithHTTPClient(&http.Client{Timeout: 15 * time.Second}),
	)
	return &cloudflareBackend{api: &cloudflareSDK{client: client}}, nil
}

// cloudflareBackend 将 Cloudflare 记录转换为统一冲突模型。
type cloudflareBackend struct {
	api cloudflareAPI // api 便于使用模拟 API 测试分页与写入行为。
}

// ListZones 通过官方 SDK 查询一页启用状态由调用方核验的托管区。
func (s *cloudflareSDK) ListZones(ctx context.Context, name string, page int64) ([]cfzones.Zone, error) {
	result, err := s.client.Zones.List(ctx, cfzones.ZoneListParams{
		Name:    cloudflare.F(name),
		Page:    cloudflare.F(float64(page)),
		PerPage: cloudflare.F(float64(cloudflareZonePageSize)),
	})
	if err != nil {
		return nil, err
	}
	return result.Result, nil
}

// ListRecords 查询一页所有类型记录，精确匹配完整记录名且不跟随 CNAME。
func (s *cloudflareSDK) ListRecords(ctx context.Context, zoneID string, fqdn string, page int64) ([]cfdns.RecordResponse, error) {
	result, err := s.client.DNS.Records.List(ctx, cfdns.RecordListParams{
		ZoneID:  cloudflare.F(zoneID),
		Name:    cloudflare.F(cfdns.RecordListParamsName{Exact: cloudflare.F(fqdn)}),
		Page:    cloudflare.F(float64(page)),
		PerPage: cloudflare.F(float64(cloudflareRecordPageSize)),
	})
	if err != nil {
		return nil, err
	}
	return result.Result, nil
}

// CreateRecord 仅新增 TTL 600、DNS only 的 CNAME，并回传 Cloudflare Ray ID。
func (s *cloudflareSDK) CreateRecord(ctx context.Context, zoneID string, record *deployPB.DnsRecord) (string, error) {
	var response *http.Response
	_, err := s.client.DNS.Records.New(ctx, cfdns.RecordNewParams{
		ZoneID: cloudflare.F(zoneID),
		Body: cfdns.CNAMERecordParam{
			Name:    cloudflare.F(record.Fqdn),
			Type:    cloudflare.F(cfdns.CNAMERecordTypeCNAME),
			Content: cloudflare.F(record.Value),
			TTL:     cloudflare.F(cfdns.TTL(600)),
			Proxied: cloudflare.F(false),
		},
	}, option.WithResponseInto(&response))
	requestID := cloudflareRequestID(response)
	if err != nil && response != nil {
		err = cloudflareStatusError{status: response.StatusCode, err: err}
	}
	return requestID, err
}

// FindZone 精确查找完整托管区，只接受 Cloudflare 已激活的 Zone。
func (b *cloudflareBackend) FindZone(ctx context.Context, zone string) (string, error) {
	for page := int64(1); page <= cloudflareMaxPages; page++ {
		zones, err := b.api.ListZones(ctx, zone, page)
		if err != nil {
			return "", err
		}
		for _, item := range zones {
			if Normalize(item.Name) == Normalize(zone) && strings.EqualFold(string(item.Status), "active") && item.ID != "" {
				return item.ID, nil
			}
		}
		if len(zones) < cloudflareZonePageSize {
			return "", fmt.Errorf("Cloudflare zone inaccessible")
		}
	}
	return "", fmt.Errorf("Cloudflare zone pagination incomplete")
}

// List 分页读取完整记录名上的全部类型，并将代理记录标记为不可复用冲突。
func (b *cloudflareBackend) List(ctx context.Context, zoneID string, record *deployPB.DnsRecord) ([]Entry, error) {
	var entries []Entry
	for page := int64(1); page <= cloudflareMaxPages; page++ {
		records, err := b.api.ListRecords(ctx, zoneID, record.Fqdn, page)
		if err != nil {
			return nil, err
		}
		for _, item := range records {
			if Normalize(item.Name) != Normalize(record.Fqdn) {
				continue
			}
			entries = append(entries, Entry{
				Host:        item.Name,
				Type:        string(item.Type),
				Value:       item.Content,
				Enabled:     true,
				DefaultLine: !item.Proxied,
			})
		}
		if len(records) < cloudflareRecordPageSize {
			return entries, nil
		}
	}
	return nil, fmt.Errorf("Cloudflare DNS record pagination incomplete")
}

// Create 新增 Cloudflare DNS only 默认 CNAME。
func (b *cloudflareBackend) Create(ctx context.Context, zoneID string, record *deployPB.DnsRecord) (string, error) {
	return b.api.CreateRecord(ctx, zoneID, record)
}

// cloudflareRequestID 只读取可展示的 Cloudflare Ray ID。
func cloudflareRequestID(response *http.Response) string {
	if response == nil {
		return ""
	}
	if rayID := strings.TrimSpace(response.Header.Get("CF-Ray")); rayID != "" {
		return rayID
	}
	return strings.TrimSpace(response.Header.Get("X-Request-ID"))
}

// cloudflareStatusError 将 HTTP 状态加入内部错误分类且保留 SDK 错误链。
type cloudflareStatusError struct {
	status int   // status 是 Cloudflare API 返回的 HTTP 状态码。
	err    error // err 是 SDK 的原始错误，仅用于内部分类。
}

// Error 返回不包含凭据的 Cloudflare HTTP 状态。
func (e cloudflareStatusError) Error() string {
	return fmt.Sprintf("Cloudflare API status %d: %v", e.status, e.err)
}

// Unwrap 保留 SDK 错误链用于 errors.As/errors.Is。
func (e cloudflareStatusError) Unwrap() error {
	return e.err
}

// GetStatusCode 提供 SDK HTTP 状态码以区分权限错误。
func (e cloudflareStatusError) GetStatusCode() *int {
	return &e.status
}
