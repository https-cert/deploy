package dnsconfig

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	cloudflare "github.com/cloudflare/cloudflare-go/v4"
	"github.com/cloudflare/cloudflare-go/v4/option"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// TestCloudflareBackendFindZoneRequiresActiveExactZone 验证只接受精确且已激活的托管区。
func TestCloudflareBackendFindZoneRequiresActiveExactZone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zones" || r.URL.Query().Get("name") != "api.example.com" {
			t.Errorf("Zone 查询参数错误：%s %s", r.Method, r.URL.String())
		}
		writeCloudflareJSON(t, w, http.StatusOK, map[string]any{
			"result":      []map[string]any{{"id": "zone-id", "name": "API.EXAMPLE.COM.", "status": "active"}},
			"result_info": map[string]any{"page": 1, "per_page": cloudflareZonePageSize},
		})
	}))
	defer server.Close()

	backend := cloudflareTestBackend(server.URL)
	zoneID, err := backend.FindZone(context.Background(), "api.example.com")
	if err != nil || zoneID != "zone-id" {
		t.Fatalf("Cloudflare Zone 查询失败：%q %v", zoneID, err)
	}
}

// TestCloudflareBackendListPaginatesAndFlagsProxiedRecords 验证分页冲突不会被遗漏，代理记录不能复用。
func TestCloudflareBackendListPaginatesAndFlagsProxiedRecords(t *testing.T) {
	var requestedPages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zones/zone-id/dns_records" || r.URL.Query().Get("name.exact") != "_acme-challenge.api.example.com" {
			t.Errorf("DNS 查询未精确匹配完整记录名：%s", r.URL.String())
		}
		requestedPages = append(requestedPages, r.URL.Query().Get("page"))
		rows := make([]map[string]any, 0, cloudflareRecordPageSize)
		if r.URL.Query().Get("page") == "1" {
			for index := 0; index < cloudflareRecordPageSize; index++ {
				rows = append(rows, map[string]any{
					"id": fmt.Sprintf("other-%d", index), "name": fmt.Sprintf("other-%d.api.example.com", index),
					"type": "TXT", "content": "unrelated", "ttl": 600, "proxied": false,
				})
			}
		} else {
			rows = append(rows, map[string]any{
				"id": "proxied", "name": "_acme-challenge.api.example.com", "type": "CNAME",
				"content": "target.example.net", "ttl": 600, "proxied": true,
			})
		}
		writeCloudflareJSON(t, w, http.StatusOK, map[string]any{
			"result":      rows,
			"result_info": map[string]any{"page": r.URL.Query().Get("page"), "per_page": cloudflareRecordPageSize},
		})
	}))
	defer server.Close()

	backend := cloudflareTestBackend(server.URL)
	entries, err := backend.List(context.Background(), "zone-id", testRecord())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || len(requestedPages) != 2 || requestedPages[0] != "1" || requestedPages[1] != "2" {
		t.Fatalf("DNS 分页查询不完整：记录数=%d 页码=%v", len(entries), requestedPages)
	}
	if got := Classify(entries, testRecord()); got != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_CONFLICT {
		t.Fatalf("被代理 CNAME 未作为冲突：%v", got)
	}
}

// TestCloudflareBackendCreateUsesDNSOnlyAndReturnsRayID 验证 Token、TTL、CNAME 及 DNS only 写入参数。
func TestCloudflareBackendCreateUsesDNSOnlyAndReturnsRayID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/zones/zone-id/dns_records" {
			t.Errorf("新增 CNAME 请求路径错误：%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-cloudflare-token" {
			t.Errorf("Cloudflare Token 未被 SDK 使用")
		}
		var body map[string]any
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			t.Errorf("解析新增请求失败：%v", err)
		}
		if body["name"] != "_acme-challenge.api.example.com" || body["content"] != "target.example.net" || body["type"] != "CNAME" || body["ttl"] != float64(600) || body["proxied"] != false {
			t.Errorf("新增记录参数错误：%v", body)
		}
		w.Header().Set("CF-Ray", "cloudflare-ray-id")
		writeCloudflareJSON(t, w, http.StatusOK, map[string]any{
			"result": map[string]any{
				"id": "record-id", "name": "_acme-challenge.api.example.com", "type": "CNAME",
				"content": "target.example.net", "ttl": 600, "proxied": false,
			},
		})
	}))
	defer server.Close()

	backend := cloudflareTestBackend(server.URL)
	requestID, err := backend.Create(context.Background(), "zone-id", testRecord())
	if err != nil || requestID != "cloudflare-ray-id" {
		t.Fatalf("新增请求结果错误：%q %v", requestID, err)
	}
}

// TestCloudflareBackendCreatePreservesDeniedStatusAndRayID 验证新增权限错误仍返回 Cloudflare 请求标识。
func TestCloudflareBackendCreatePreservesDeniedStatusAndRayID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("CF-Ray", "cloudflare-denied-ray")
		writeCloudflareJSON(t, w, http.StatusForbidden, map[string]any{
			"success": false,
			"errors":  []map[string]any{{"code": 10000, "message": "permission denied"}},
			"result":  nil,
		})
	}))
	defer server.Close()

	backend := cloudflareTestBackend(server.URL)
	requestID, err := backend.Create(context.Background(), "zone-id", testRecord())
	if err == nil || requestID != "cloudflare-denied-ray" {
		t.Fatalf("权限拒绝或 Cloudflare Ray ID 丢失：%q %v", requestID, err)
	}
	result := failure(&deployPB.DnsOperationResult{ProviderRequestId: requestID}, err, true)
	if result.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_PERMISSION_DENIED {
		t.Fatalf("权限拒绝状态映射错误：%v", result.Status)
	}
}

// TestCloudflareCapabilitiesRequireLocalToken 验证 Cloudflare 能力只由本地 Token 决定。
func TestCloudflareCapabilitiesRequireLocalToken(t *testing.T) {
	runtime := &config.Runtime{Config: &config.Configuration{Provider: []*config.Provider{{
		Name: config.ProviderCloudflare,
		Auth: &config.ProviderAuth{APIToken: " token "},
	}}}}
	for _, capability := range Capabilities(runtime) {
		if capability.Provider == deployPB.DnsProvider_DNS_PROVIDER_CLOUDFLARE {
			if !capability.Configured {
				t.Fatal("Cloudflare Token 已配置但能力未上报")
			}
			return
		}
	}
	t.Fatal("Cloudflare 能力未注册")
}

// cloudflareTestBackend 创建连接本地 HTTP 模拟服务的真实 Cloudflare SDK。
func cloudflareTestBackend(baseURL string) *cloudflareBackend {
	client := cloudflare.NewClient(
		option.WithAPIToken("test-cloudflare-token"),
		option.WithBaseURL(baseURL),
	)
	return &cloudflareBackend{api: &cloudflareSDK{client: client}}
}

// writeCloudflareJSON 返回 Cloudflare V4 API 格式响应。
func writeCloudflareJSON(t *testing.T, w http.ResponseWriter, status int, value map[string]any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.MarshalWrite(w, value); err != nil {
		t.Errorf("写入模拟 Cloudflare 响应失败：%v", err)
	}
}
