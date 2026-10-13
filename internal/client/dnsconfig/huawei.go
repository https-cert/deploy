package dnsconfig

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	sdkconfig "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/httphandler"
	api "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2"
	model "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/region"
)

// huaweiAPI 隔离云 SDK，测试不请求真实账户。
type huaweiAPI interface {
	// ListPublicZones 读取公网区。
	ListPublicZones(*model.ListPublicZonesRequest) (*model.ListPublicZonesResponse, error)
	// ListRecordSetsWithLine 查询全部线路。
	ListRecordSetsWithLine(*model.ListRecordSetsWithLineRequest) (*model.ListRecordSetsWithLineResponse, error)
	// CreateRecordSet 新建默认记录。
	CreateRecordSet(*model.CreateRecordSetRequest) (*model.CreateRecordSetResponse, error)
}

// huaweiBackend 使用公网 DNS 客户端，查询含线路的记录集。
type huaweiBackend struct {
	api       huaweiAPI              // api 是官方 DNS 客户端。
	requestID atomic.Pointer[string] // requestID 只保存响应头中的请求标识，避免收集凭据或响应正文。
}

// newHuawei 使用用户地域构建 DNS 客户端。
func newHuawei(p *config.Provider) (Backend, error) {
	name := p.Region
	if name == "" {
		name = "cn-north-4"
	}
	location, err := region.SafeValueOf(name)
	if err != nil {
		return nil, err
	}
	credential, err := basic.NewCredentialsBuilder().WithAk(p.GetAccessKeyId()).WithSk(p.GetAccessKeySecret()).SafeBuild()
	if err != nil {
		return nil, err
	}
	backend := &huaweiBackend{}
	handler := httphandler.NewHttpHandler().AddResponseHandler(backend.captureResponse)
	client, err := api.DnsClientBuilder().WithRegion(location).WithCredential(credential).WithHttpConfig(sdkconfig.DefaultHttpConfig().WithTimeout(15 * time.Second).WithHttpHandler(handler)).SafeBuild()
	if err != nil {
		return nil, err
	}
	backend.api = api.NewDnsClient(client)
	return backend, nil
}

// captureResponse 读取官方 SDK 的请求 ID；回读请求不会改变已返回的创建结果。
func (b *huaweiBackend) captureResponse(response http.Response) {
	b.requestID.Store(new(response.Header.Get("X-Request-Id")))
}

// FindZone 分页精确查询公网权威区。
func (b *huaweiBackend) FindZone(ctx context.Context, zone string) (string, error) {
	for offset := int32(0); offset < 10000; offset += 100 {
		if err := contextCheck(ctx); err != nil {
			return "", err
		}
		reply, err := b.api.ListPublicZones(&model.ListPublicZonesRequest{Name: new(zone), Offset: new(offset), Limit: new(int32(100))})
		if err != nil {
			return "", err
		}
		if reply == nil || reply.Zones == nil {
			return "", fmt.Errorf("DNS response empty")
		}
		zones := ptrValue(reply.Zones)
		for _, item := range zones {
			if Normalize(ptrValue(item.Name)) == zone && ptrValue(item.Status) == "ACTIVE" {
				return ptrValue(item.Id), nil
			}
		}
		if len(zones) < 100 {
			return "", fmt.Errorf("DNS zone inaccessible")
		}
	}
	return "", fmt.Errorf("DNS pagination incomplete")
}

// List 使用带线路的查询接口，避免将非默认线路当成可用 CNAME。
func (b *huaweiBackend) List(ctx context.Context, zone string, r *deployPB.DnsRecord) ([]Entry, error) {
	var entries []Entry
	for offset := int32(0); offset < 10000; offset += 100 {
		if err := contextCheck(ctx); err != nil {
			return nil, err
		}
		reply, err := b.api.ListRecordSetsWithLine(&model.ListRecordSetsWithLineRequest{ZoneId: new(zone), Name: new(r.Fqdn + "."), Offset: new(offset), Limit: new(int32(100))})
		if err != nil {
			return nil, err
		}
		if reply == nil || reply.Recordsets == nil {
			return nil, fmt.Errorf("DNS response empty")
		}
		records := ptrValue(reply.Recordsets)
		for _, item := range records {
			values := ptrValue(item.Records)
			if len(values) == 0 {
				values = []string{""}
			}
			for _, value := range values {
				entries = append(entries, Entry{ptrValue(item.Name), ptrValue(item.Type), value, ptrValue(item.Status) == "ACTIVE", ptrValue(item.Line) == "default"})
			}
		}
		if len(records) < 100 {
			return entries, ctx.Err()
		}
	}
	return nil, fmt.Errorf("DNS pagination incomplete")
}

// Create 新建默认线路记录集，末尾点遵循华为 DNS 契约。
func (b *huaweiBackend) Create(ctx context.Context, zone string, r *deployPB.DnsRecord) (string, error) {
	if err := contextCheck(ctx); err != nil {
		return "", err
	}
	b.requestID.Store(nil)
	_, err := b.api.CreateRecordSet(&model.CreateRecordSetRequest{ZoneId: zone, Body: &model.CreateRecordSetRequestBody{Name: r.Fqdn + ".", Type: "CNAME", Ttl: new(int32(600)), Records: []string{r.Value + "."}}})
	return ptrValue(b.requestID.Load()), err
}
