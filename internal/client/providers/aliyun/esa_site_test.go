package aliyun

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// esaTestAPI 用官方响应字段模拟 ESA，不调用真实云账号。
type esaTestAPI struct {
	sites        []map[string]any  // sites 是分页站点目录。
	records      []map[string]any  // records 仅供历史 Record 目标解析。
	certificates []map[string]any  // certificates 是站点中已有的证书元数据。
	certificate  string            // certificate 是 GetCertificate 回读的 PEM。
	requests     []cloudAPIRequest // requests 记录请求顺序及参数。
	writes       int               // writes 记录写入次数。
	failAction   string            // failAction 指定失败的 API。
	failPage     int               // failPage 指定站点目录失败的页码。
	wrongSite    bool              // wrongSite 模拟回读到了其他站点。
	wrongPEM     bool              // wrongPEM 模拟回读内容不一致。
	missingID    bool              // missingID 模拟上传响应缺少证书 ID。
}

// Call 按官方 PageNumber/PageSize 和站点级证书接口处理请求。
func (f *esaTestAPI) Call(ctx context.Context, request cloudAPIRequest) (cloudAPIResponse, error) {
	if err := ctx.Err(); err != nil {
		return cloudAPIResponse{}, err
	}
	f.requests = append(f.requests, request)
	page, _ := strconv.Atoi(request.Query["PageNumber"])
	if request.Action == f.failAction || request.Action == "ListSites" && page == f.failPage {
		return cloudAPIResponse{}, fmt.Errorf("mock API failure")
	}
	body := map[string]any{}
	switch request.Action {
	case "ListSites", "ListRecords", "ListCertificates":
		size, _ := strconv.Atoi(request.Query["PageSize"])
		if page < 1 || size < 1 || request.Query["NextToken"] != "" || request.Query["MaxResults"] != "" {
			return cloudAPIResponse{}, fmt.Errorf("ESA 分页参数不符合官方契约")
		}
		records, key := f.sites, "Sites"
		if request.Action == "ListRecords" {
			records, key = f.records, "Records"
		} else if request.Action == "ListCertificates" {
			records, key = f.certificates, "Result"
		}
		start := min((page-1)*size, len(records))
		end := min(start+size, len(records))
		body[key], body["TotalCount"] = records[start:end], len(records)
	case "SetCertificate":
		if request.Body["SiteId"] != "1" || request.Body["Type"] != "upload" || request.Body["Certificate"] == "" || request.Body["PrivateKey"] == "" {
			return cloudAPIResponse{}, fmt.Errorf("站点上传参数不完整")
		}
		f.writes++
		f.certificate = request.Body["Certificate"]
		fingerprint, err := providers.LeafCertificateSHA256(f.certificate)
		if err != nil {
			return cloudAPIResponse{}, err
		}
		f.certificates = []map[string]any{{"Id": "cert-1", "Name": request.Body["Name"], "Type": "upload", "FingerprintSha256": fingerprint, "Status": "OK"}}
		if !f.missingID {
			body["Id"] = "cert-1"
		}
	case "GetCertificate":
		body = map[string]any{"SiteId": "1", "Status": "OK", "Certificate": f.certificate, "Result": map[string]any{"Id": "cert-1", "Status": "OK"}}
		if request.Query["SiteId"] != "1" || request.Query["Id"] != "cert-1" {
			return cloudAPIResponse{}, fmt.Errorf("证书回读定位错误")
		}
		if f.wrongSite {
			body["SiteId"] = "2"
		}
		if f.wrongPEM {
			body["Certificate"] = "invalid PEM"
		}
	default:
		return cloudAPIResponse{}, fmt.Errorf("unexpected ESA action: %s", request.Action)
	}
	return cloudAPIResponse{RequestID: "request-" + request.Action, Body: body}, nil
}

// newESATestProvider 创建离线 provider，站点 ID 固定以便校验所有 API 的定位参数。
func newESATestProvider(api *esaTestAPI) *Provider {
	if api.sites == nil {
		api.sites = []map[string]any{{"SiteId": "1", "SiteName": "example.com", "Status": "active"}}
	}
	return &Provider{AccessKeyId: "test-key", AccessKeySecret: "test-secret", deploymentAPI: api}
}

// TestESASiteCatalogWithoutRecords 验证没有 DNS 记录时仍能发现全部站点，并正确处理分页和状态。
func TestESASiteCatalogWithoutRecords(t *testing.T) {
	api := &esaTestAPI{failAction: "ListRecords"}
	for i := 1; i <= aliyunCatalogPageSize+1; i++ {
		api.sites = append(api.sites, map[string]any{"SiteId": i, "SiteName": fmt.Sprintf("site%d.example.com", i), "Status": "active"})
	}
	api.sites[0]["Status"], api.sites[1]["Status"] = "pending", "offline"
	p := newESATestProvider(api)
	catalog := p.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA)
	if catalog.Error != nil || len(catalog.Resources) != 101 || len(api.requests) != 2 {
		t.Fatalf("站点发现或分页失败: resources=%d requests=%d err=%v", len(catalog.Resources), len(api.requests), catalog.Error)
	}
	for _, resource := range catalog.Resources {
		if resource.SiteDomain != resource.Domain || resource.SiteDomain == "" {
			t.Fatal("站点资源必须携带明确的站点域名")
		}
		if resource.Status == "pending" && resource.Availability != deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY {
			t.Fatal("待配置站点应允许预先上传证书")
		}
		if resource.Status == "offline" && resource.Availability == deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY {
			t.Fatal("已下线站点不可部署")
		}
	}
	api.failPage = 2
	partial := p.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA)
	if partial.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL || len(partial.Resources) != 100 {
		t.Fatalf("后续页失败应保留已发现站点: status=%v count=%d", partial.Status, len(partial.Resources))
	}
}

// TestESALegacyRecordResolution 验证旧引用仍按 Record 精确解析，不放宽历史域名校验。
func TestESALegacyRecordResolution(t *testing.T) {
	api := &esaTestAPI{records: []map[string]any{{"RecordId": "2", "RecordName": "www.example.com"}}}
	p := newESATestProvider(api)
	ref := providers.BuildTargetRef("aliyun", deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, "1", "2")
	resource, err := p.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, ref)
	if err != nil || resource.TargetRef != ref || resource.Domain != "www.example.com" || resource.SiteDomain != "" {
		t.Fatalf("历史 Record 解析失败: resource=%+v err=%v", resource, err)
	}
	if _, err := p.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, "stale-ref"); err == nil {
		t.Fatal("失效引用不能自动扩大到整个站点")
	}
}

// TestESASiteCertificateUploadAndRenewal 验证子域证书无 Record 上传、重试幂等及续期复用同一证书 ID。
func TestESASiteCertificateUploadAndRenewal(t *testing.T) {
	api := &esaTestAPI{failAction: "ListRecords"}
	p := newESATestProvider(api)
	resource := p.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA).Resources[0]
	if err := p.TestResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, resource.TargetRef); err != nil {
		t.Fatalf("没有证书和记录的站点应可测试: %v", err)
	}
	certificate := generateAliyunCertificate(t, "www.example.com")
	for i := 0; i < 2; i++ {
		if _, err := p.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, resource); err != nil {
			t.Fatalf("站点证书上传或幂等回读失败: %v", err)
		}
	}
	if api.writes != 1 {
		t.Fatalf("相同证书重复执行不应重复上传: writes=%d", api.writes)
	}
	renewed := generateAliyunCertificate(t, "www.example.com")
	if _, err := p.DeployCertificate(context.Background(), renewed, deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, resource); err != nil {
		t.Fatalf("证书续期失败: %v", err)
	}
	if api.writes != 2 {
		t.Fatalf("续期应更新一次: writes=%d", api.writes)
	}
	for i := len(api.requests) - 1; i >= 0; i-- {
		if api.requests[i].Action == "SetCertificate" {
			if api.requests[i].Body["Id"] != "cert-1" {
				t.Fatal("续期必须复用托管证书 ID")
			}
			break
		}
	}
}

// TestESASiteDeploymentRejectsUnconfirmedResults 验证错误站点、错误 PEM 和缺少 ID 时不会报告成功。
func TestESASiteDeploymentRejectsUnconfirmedResults(t *testing.T) {
	certificate := generateAliyunCertificate(t, "www.example.com")
	for _, scenario := range []string{"wrong-site", "wrong-pem", "missing-id", "list-failure", "foreign-domain"} {
		t.Run(scenario, func(t *testing.T) {
			api := &esaTestAPI{wrongSite: scenario == "wrong-site", wrongPEM: scenario == "wrong-pem", missingID: scenario == "missing-id"}
			if scenario == "list-failure" {
				api.failAction = "ListCertificates"
			}
			p := newESATestProvider(api)
			resource := p.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA).Resources[0]
			if scenario == "foreign-domain" {
				resource.SiteDomain = "other.example.net"
			}
			if _, err := p.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, resource); err == nil {
				t.Fatal("未确认的部署不能返回成功")
			}
			if (scenario == "list-failure" || scenario == "foreign-domain") && api.writes != 0 {
				t.Fatal("预检失败时不得写入证书")
			}
		})
	}
}
