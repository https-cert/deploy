package qiniu

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// qiniuHTTPClientFunc 将函数适配为离线测试 HTTP 客户端。
type qiniuHTTPClientFunc func(*http.Request) (*http.Response, error)

// Do 执行测试定义的请求逻辑。
func (function qiniuHTTPClientFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

// TestDiscoverResourcesAndResolveExactTarget 验证成功发现和精确 targetRef 解析。
func TestDiscoverResourcesAndResolveExactTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/domain":
			_, _ = writer.Write([]byte(`{"domains":[{"name":"cdn.example.com"}],"marker":""}`))
		case "/domain/cdn.example.com":
			_, _ = writer.Write([]byte(`{"name":"cdn.example.com","product":"cdn","protocol":"https","operatingState":"success","createAt":"2026-01-01T00:00:00Z","https":{"certId":"old"}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newQiniuTestProvider(server)

	catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY || len(catalog.Resources) != 1 {
		t.Fatalf("unexpected catalog: %#v", catalog)
	}
	resource := catalog.Resources[0]
	resolved, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef)
	if err != nil {
		t.Fatalf("ResolveResource() error = %v", err)
	}
	if resolved.Domain != "cdn.example.com" || resolved.TargetRef != resource.TargetRef {
		t.Fatalf("resolved resource = %#v", resolved)
	}
	if _, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "qiniu:missing"); err == nil {
		t.Fatal("ResolveResource() unexpectedly accepted stale targetRef")
	}
}

// TestDiscoverResourcesEmptyPartialAndPermissionDenied 验证空目录、部分成功和权限不足状态。
func TestDiscoverResourcesEmptyPartialAndPermissionDenied(t *testing.T) {
	tests := []struct {
		name          string
		listStatus    int
		listBody      string
		detailFailure bool
		wantStatus    deployPB.DeploymentResourceStatus
		wantResources int
	}{
		{name: "empty", listStatus: http.StatusOK, listBody: `{"domains":[],"marker":""}`, wantStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY},
		{name: "partial", listStatus: http.StatusOK, listBody: `{"domains":[{"name":"good.example.com"},{"name":"bad.example.com"}],"marker":""}`, detailFailure: true, wantStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL, wantResources: 1},
		{name: "permission", listStatus: http.StatusForbidden, listBody: `{"error":"forbidden"}`, wantStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				if request.URL.Path == "/domain" {
					writer.WriteHeader(test.listStatus)
					_, _ = writer.Write([]byte(test.listBody))
					return
				}
				if test.detailFailure && strings.Contains(request.URL.Path, "bad.example.com") {
					http.Error(writer, `{"error":"temporary"}`, http.StatusServiceUnavailable)
					return
				}
				_, _ = writer.Write([]byte(`{"name":"good.example.com","product":"cdn","protocol":"https","operatingState":"success","createAt":"2026-01-01T00:00:00Z"}`))
			}))
			defer server.Close()
			catalog := newQiniuTestProvider(server).DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
			if catalog.Status != test.wantStatus || len(catalog.Resources) != test.wantResources {
				t.Fatalf("catalog status=%s resources=%d error=%v", catalog.Status, len(catalog.Resources), catalog.Error)
			}
		})
	}
}

// TestDiscoverResourcesHonorsCancellation 验证资源发现把调用方取消传给 HTTP 请求。
func TestDiscoverResourcesHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider := NewWithOptions("access", "secret", &Options{
		HTTPClient: qiniuHTTPClientFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		}),
		APIBaseURL:    "https://qiniu.invalid",
		FusionBaseURL: "https://qiniu.invalid",
	})
	catalog := provider.DiscoverResources(ctx, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE || !errors.Is(catalog.Error, context.Canceled) {
		t.Fatalf("canceled catalog = %#v", catalog)
	}
}

// TestDeployCertificateUsesExactDomainAndReadsBackCertID 验证一次 fake 部署完整执行上传、绑定和回读。
func TestDeployCertificateUsesExactDomainAndReadsBackCertID(t *testing.T) {
	var bound atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Reqid", "request-123")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/domain/cdn.example.com":
			certID := "old"
			if bound.Load() {
				certID = "cert-new"
			}
			_, _ = writer.Write([]byte(`{"name":"cdn.example.com","product":"cdn","protocol":"https","operatingState":"success","createAt":"2026-01-01T00:00:00Z","https":{"certId":"` + certID + `"}}`))
		case request.Method == http.MethodPost && request.URL.Path == "/sslcert":
			_, _ = writer.Write([]byte(`{"certID":"cert-new"}`))
		case request.Method == http.MethodPut && request.URL.Path == "/domain/cdn.example.com/httpsconf":
			bound.Store(true)
			_, _ = writer.Write([]byte(`{}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newQiniuTestProvider(server)
	result, err := provider.DeployCertificate(context.Background(), providers.CertificateMaterial{
		Name:           "certificate",
		Domain:         "cdn.example.com",
		CertificatePEM: "certificate-pem",
		PrivateKeyPEM:  "private-key-pem",
	}, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, providers.DeploymentResource{
		TargetRef: "qiniu-target",
		Domain:    "cdn.example.com",
	})
	if err != nil {
		t.Fatalf("DeployCertificate() error = %v", err)
	}
	if !bound.Load() || result.RequestID != "request-123" {
		t.Fatalf("deployment result=%#v bound=%v", result, bound.Load())
	}
}

// newQiniuTestProvider 创建使用同一个 httptest 服务的七牛 provider。
func newQiniuTestProvider(server *httptest.Server) *Provider {
	return NewWithOptions("access", "secret", &Options{HTTPClient: server.Client(), APIBaseURL: server.URL, FusionBaseURL: server.URL})
}
