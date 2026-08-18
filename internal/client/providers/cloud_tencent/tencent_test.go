package cloud_tencent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	tencentcdn "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdn/v20180606"
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tencenterrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// fakeTencentCDNClient 用回调替代腾讯云 CDN SDK 调用。
type fakeTencentCDNClient struct {
	describe func(context.Context, *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) // describe 处理目录和精确域名查询。
	update   func(context.Context, *tencentcdn.UpdateDomainConfigRequest) (*tencentcdn.UpdateDomainConfigResponse, error)       // update 处理证书配置写入。
}

// DescribeDomainsConfigWithContext 调用测试提供的 CDN 查询回调。
func (f *fakeTencentCDNClient) DescribeDomainsConfigWithContext(ctx context.Context, request *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) {
	if f.describe == nil {
		return nil, errors.New("未配置 CDN 查询回调")
	}
	return f.describe(ctx, request)
}

// UpdateDomainConfigWithContext 调用测试提供的 CDN 更新回调。
func (f *fakeTencentCDNClient) UpdateDomainConfigWithContext(ctx context.Context, request *tencentcdn.UpdateDomainConfigRequest) (*tencentcdn.UpdateDomainConfigResponse, error) {
	if f.update == nil {
		return nil, errors.New("未配置 CDN 更新回调")
	}
	return f.update(ctx, request)
}

// fakeTencentSSLClient 用回调替代腾讯云 SSL SDK 调用。
type fakeTencentSSLClient struct {
	describeCertificates func(context.Context, *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error)           // describeCertificates 处理连接测试查询。
	describeDetail       func(context.Context, *ssl.DescribeCertificateDetailRequest) (*ssl.DescribeCertificateDetailResponse, error) // describeDetail 处理证书指纹回读。
	upload               func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error)                 // upload 处理证书上传。
}

// DescribeCertificatesWithContext 调用测试提供的证书列表回调。
func (f *fakeTencentSSLClient) DescribeCertificatesWithContext(ctx context.Context, request *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error) {
	if f.describeCertificates == nil {
		return nil, errors.New("未配置 SSL 列表回调")
	}
	return f.describeCertificates(ctx, request)
}

// DescribeCertificateDetailWithContext 调用测试提供的证书详情回调。
func (f *fakeTencentSSLClient) DescribeCertificateDetailWithContext(ctx context.Context, request *ssl.DescribeCertificateDetailRequest) (*ssl.DescribeCertificateDetailResponse, error) {
	if f.describeDetail == nil {
		return nil, errors.New("未配置 SSL 详情回调")
	}
	return f.describeDetail(ctx, request)
}

// UploadCertificateWithContext 调用测试提供的证书上传回调。
func (f *fakeTencentSSLClient) UploadCertificateWithContext(ctx context.Context, request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
	if f.upload == nil {
		return nil, errors.New("未配置 SSL 上传回调")
	}
	return f.upload(ctx, request)
}

// TestProviderDiscoverCDNResources 验证 CDN 目录的成功、空目录、权限不足和取消状态。
func TestProviderDiscoverCDNResources(t *testing.T) {
	tests := []struct {
		name           string                            // name 是子测试名称。
		contextFactory func() context.Context            // contextFactory 创建本次发现使用的 context。
		describe       fakeTencentCDNDescribe            // describe 模拟腾讯云 CDN 查询。
		wantStatus     deployPB.DeploymentResourceStatus // wantStatus 是期望目录状态。
		wantResources  int                               // wantResources 是期望资源数量。
	}{
		{
			name:           "成功",
			contextFactory: context.Background,
			describe: func(_ context.Context, _ *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) {
				return newTencentCDNResponse([]*tencentcdn.DetailDomain{newTencentCDNDetail("www.example.com", "cert-old")}, 1), nil
			},
			wantStatus:    deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY,
			wantResources: 1,
		},
		{
			name:           "空目录",
			contextFactory: context.Background,
			describe: func(_ context.Context, _ *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) {
				return newTencentCDNResponse(nil, 0), nil
			},
			wantStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY,
		},
		{
			name:           "权限不足",
			contextFactory: context.Background,
			describe: func(_ context.Context, _ *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) {
				return nil, tencenterrors.NewTencentCloudSDKError("AuthFailure.UnauthorizedOperation", "denied", "request-denied")
			},
			wantStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED,
		},
		{
			name: "取消",
			contextFactory: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			describe: func(ctx context.Context, _ *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) {
				return nil, ctx.Err()
			},
			wantStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newTencentCDNTestProvider(test.describe, nil)
			catalog := provider.DiscoverResources(test.contextFactory(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
			if catalog.Status != test.wantStatus {
				t.Fatalf("目录状态不匹配: got=%s want=%s err=%v", catalog.Status, test.wantStatus, catalog.Error)
			}
			if len(catalog.Resources) != test.wantResources {
				t.Fatalf("资源数量不匹配: got=%d want=%d", len(catalog.Resources), test.wantResources)
			}
		})
	}
}

// TestProviderDiscoverCDNPaginationAndPartial 验证分页停止条件和后续页失败时的部分成功状态。
func TestProviderDiscoverCDNPaginationAndPartial(t *testing.T) {
	firstPage := make([]*tencentcdn.DetailDomain, 0, tencentCatalogPageSize)
	for index := 0; index < tencentCatalogPageSize; index++ {
		firstPage = append(firstPage, newTencentCDNDetail("page-"+big.NewInt(int64(index)).String()+".example.com", "cert-old"))
	}

	t.Run("分页停止", func(t *testing.T) {
		calls := 0
		provider := newTencentCDNTestProvider(func(_ context.Context, request *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) {
			calls++
			if int64Value(request.Offset) == 0 {
				return newTencentCDNResponse(firstPage, 101), nil
			}
			return newTencentCDNResponse([]*tencentcdn.DetailDomain{newTencentCDNDetail("last.example.com", "cert-old")}, 101), nil
		}, nil)
		catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
		if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY || len(catalog.Resources) != 101 || calls != 2 {
			t.Fatalf("分页结果不匹配: status=%s resources=%d calls=%d err=%v", catalog.Status, len(catalog.Resources), calls, catalog.Error)
		}
	})

	t.Run("部分成功", func(t *testing.T) {
		provider := newTencentCDNTestProvider(func(_ context.Context, request *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) {
			if int64Value(request.Offset) == 0 {
				return newTencentCDNResponse(firstPage, 200), nil
			}
			return nil, errors.New("第二页临时失败")
		}, nil)
		catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
		if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL || len(catalog.Resources) != tencentCatalogPageSize {
			t.Fatalf("部分成功结果不匹配: status=%s resources=%d err=%v", catalog.Status, len(catalog.Resources), catalog.Error)
		}
	})
}

// TestProviderResolveCDNResource 验证精确 targetRef 解析并拒绝已失效引用。
func TestProviderResolveCDNResource(t *testing.T) {
	provider := newTencentCDNTestProvider(func(_ context.Context, _ *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) {
		return newTencentCDNResponse([]*tencentcdn.DetailDomain{newTencentCDNDetail("www.example.com", "cert-old")}, 1), nil
	}, nil)
	catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if len(catalog.Resources) != 1 {
		t.Fatalf("期望发现一个资源，实际 %d", len(catalog.Resources))
	}
	resource, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, catalog.Resources[0].TargetRef)
	if err != nil || resource.Domain != "www.example.com" {
		t.Fatalf("精确解析失败: resource=%+v err=%v", resource, err)
	}
	if _, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "cloudTencent:stale"); err == nil {
		t.Fatal("失效 targetRef 应返回错误")
	}
}

// TestProviderDeployCDNCertificate 验证 fake SSL 上传、CDN 更新、回读和证书指纹校验完整成功路径。
func TestProviderDeployCDNCertificate(t *testing.T) {
	certificatePEM, privateKeyPEM := generateTencentTestCertificate(t, "www.example.com")
	updated := false
	cdnClient := &fakeTencentCDNClient{
		describe: func(_ context.Context, _ *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error) {
			certificateID := "cert-old"
			if updated {
				certificateID = "cert-new"
			}
			return newTencentCDNResponse([]*tencentcdn.DetailDomain{newTencentCDNDetail("www.example.com", certificateID)}, 1), nil
		},
		update: func(_ context.Context, request *tencentcdn.UpdateDomainConfigRequest) (*tencentcdn.UpdateDomainConfigResponse, error) {
			if request == nil || stringValue(request.Domain) != "www.example.com" || request.Https == nil || request.Https.CertInfo == nil || stringValue(request.Https.CertInfo.CertId) != "cert-new" {
				t.Fatalf("CDN 更新请求不精确: %+v", request)
			}
			if stringValue(request.Https.Http2) != "on" {
				t.Fatal("CDN 更新应保留原有 HTTP/2 配置")
			}
			updated = true
			return &tencentcdn.UpdateDomainConfigResponse{Response: &tencentcdn.UpdateDomainConfigResponseParams{RequestId: tencentcommon.StringPtr("request-update")}}, nil
		},
	}
	sslClient := &fakeTencentSSLClient{
		upload: func(_ context.Context, request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			if request == nil || stringValue(request.CertificatePublicKey) != certificatePEM || stringValue(request.CertificatePrivateKey) != privateKeyPEM {
				t.Fatal("SSL 上传请求未携带精确证书材料")
			}
			return &ssl.UploadCertificateResponse{Response: &ssl.UploadCertificateResponseParams{
				CertificateId: tencentcommon.StringPtr("cert-new"),
				RequestId:     tencentcommon.StringPtr("request-upload"),
			}}, nil
		},
		describeDetail: func(_ context.Context, request *ssl.DescribeCertificateDetailRequest) (*ssl.DescribeCertificateDetailResponse, error) {
			if request == nil || stringValue(request.CertificateId) != "cert-new" {
				t.Fatal("SSL 详情回读未使用新证书 ID")
			}
			return &ssl.DescribeCertificateDetailResponse{Response: &ssl.DescribeCertificateDetailResponseParams{
				CertificateId:        tencentcommon.StringPtr("cert-new"),
				CertificatePublicKey: tencentcommon.StringPtr(certificatePEM),
				RequestId:            tencentcommon.StringPtr("request-detail"),
			}}, nil
		},
	}
	provider := New("secret-id", "secret-key")
	provider.cdnClient = cdnClient
	provider.client = sslClient
	resource, ok := tencentCDNResource(newTencentCDNDetail("www.example.com", "cert-old"))
	if !ok {
		t.Fatal("无法构造腾讯云 CDN 测试资源")
	}
	result, err := provider.DeployCertificate(context.Background(), providers.CertificateMaterial{
		Name:           "www.example.com",
		Domain:         "www.example.com",
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
	}, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource)
	if err != nil {
		t.Fatalf("CDN fake 部署失败: %v", err)
	}
	if !updated || result.RequestID != "request-update" || !strings.Contains(result.Message, "部署成功") {
		t.Fatalf("CDN 部署结果不匹配: updated=%v result=%+v", updated, result)
	}
}

// fakeTencentCDNDescribe 是 fake CDN 查询回调签名。
type fakeTencentCDNDescribe func(context.Context, *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error)

// newTencentCDNTestProvider 创建只使用 fake CDN 客户端的腾讯云 Provider。
func newTencentCDNTestProvider(describe fakeTencentCDNDescribe, update func(context.Context, *tencentcdn.UpdateDomainConfigRequest) (*tencentcdn.UpdateDomainConfigResponse, error)) *Provider {
	provider := New("secret-id", "secret-key")
	provider.cdnClient = &fakeTencentCDNClient{describe: describe, update: update}
	return provider
}

// newTencentCDNResponse 创建腾讯云 CDN 目录响应。
func newTencentCDNResponse(domains []*tencentcdn.DetailDomain, total int64) *tencentcdn.DescribeDomainsConfigResponse {
	return &tencentcdn.DescribeDomainsConfigResponse{Response: &tencentcdn.DescribeDomainsConfigResponseParams{
		Domains:     domains,
		TotalNumber: tencentcommon.Int64Ptr(total),
		RequestId:   tencentcommon.StringPtr("request-catalog"),
	}}
}

// newTencentCDNDetail 创建一个可部署的腾讯云 CDN 域名记录。
func newTencentCDNDetail(domain, certificateID string) *tencentcdn.DetailDomain {
	return &tencentcdn.DetailDomain{
		ResourceId: tencentcommon.StringPtr("resource-" + domain),
		Domain:     tencentcommon.StringPtr(domain),
		Status:     tencentcommon.StringPtr("online"),
		Disable:    tencentcommon.StringPtr("normal"),
		CreateTime: tencentcommon.StringPtr("2026-01-01 00:00:00"),
		Https: &tencentcdn.Https{
			Switch:   tencentcommon.StringPtr("on"),
			Http2:    tencentcommon.StringPtr("on"),
			CertInfo: &tencentcdn.ServerCert{CertId: tencentcommon.StringPtr(certificateID)},
		},
	}
}

// generateTencentTestCertificate 创建覆盖指定域名的离线测试证书和私钥。
func generateTencentTestCertificate(t *testing.T, domain string) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("编码测试私钥失败: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})
	return string(certificatePEM), string(privateKeyPEM)
}
