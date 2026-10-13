package dnsconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baidubce/bce-sdk-go/bce"
	bd "github.com/baidubce/bce-sdk-go/services/dns"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	sdkconfig "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/httphandler"
	hw "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2"
)

// TestBaiduRequestID 通过模拟 HTTP 响应验证官方 SDK 的成功和失败请求 ID 均被保留。
func TestBaiduRequestID(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/dns/zone/api.example.com/record" {
					t.Errorf("新增请求目标错误：%s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Bce-Request-Id", "baidu-create-id")
				w.WriteHeader(status)
				if status == http.StatusForbidden {
					_, _ = w.Write([]byte(`{"code":"AccessDenied","message":"forbidden"}`))
				} else {
					_, _ = w.Write([]byte(`{"recordId":"record-id"}`))
				}
			}))
			defer server.Close()
			client, err := bd.NewClient("test-ak", "test-sk", server.URL)
			if err != nil {
				t.Fatal(err)
			}
			client.Config.Retry = bce.NewNoRetryPolicy()
			backend := &baiduBackend{api: &baiduSDK{Client: client}}
			id, err := backend.Create(context.Background(), "api.example.com", testRecord())
			if id != "baidu-create-id" || (err != nil) != (status == http.StatusForbidden) {
				t.Fatalf("请求 ID 或失败状态丢失：%q %v", id, err)
			}
		})
	}
}

// TestHuaweiRequestID 验证响应钩子返回新增请求 ID，后续查询不会覆盖已有结果。
func TestHuaweiRequestID(t *testing.T) {
	for _, status := range []int{http.StatusCreated, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v2/zones/zone-id/recordsets" {
					t.Errorf("新增请求目标错误：%s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Request-Id", "huawei-create-id")
				w.WriteHeader(status)
				if status == http.StatusForbidden {
					_, _ = w.Write([]byte(`{"error_code":"DNS.0001","error_msg":"forbidden"}`))
				} else {
					_, _ = w.Write([]byte(`{"id":"record-id","status":"ACTIVE"}`))
				}
			}))
			defer server.Close()
			credential, err := basic.NewCredentialsBuilder().WithAk("test-ak").WithSk("test-sk").WithProjectId("project-id").SafeBuild()
			if err != nil {
				t.Fatal(err)
			}
			backend := &huaweiBackend{}
			handler := httphandler.NewHttpHandler().AddResponseHandler(backend.captureResponse)
			client, err := hw.DnsClientBuilder().WithEndpoint(server.URL).WithCredential(credential).WithHttpConfig(sdkconfig.DefaultHttpConfig().WithHttpHandler(handler)).SafeBuild()
			if err != nil {
				t.Fatal(err)
			}
			backend.api = hw.NewDnsClient(client)
			id, err := backend.Create(context.Background(), "zone-id", testRecord())
			backend.captureResponse(http.Response{Header: http.Header{"X-Request-Id": {"readback-id"}}})
			if id != "huawei-create-id" || (err != nil) != (status == http.StatusForbidden) {
				t.Fatalf("请求 ID 或失败状态丢失：%q %v", id, err)
			}
		})
	}
}
