package jdcloud

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/jdcloud-api/jdcloud-sdk-go/core"
	cdnapi "github.com/jdcloud-api/jdcloud-sdk-go/services/cdn/apis"
	cdnmodel "github.com/jdcloud-api/jdcloud-sdk-go/services/cdn/models"
	sslapi "github.com/jdcloud-api/jdcloud-sdk-go/services/ssl/apis"
	sslmodel "github.com/jdcloud-api/jdcloud-sdk-go/services/ssl/models"
)

// fakeJDCloudCDNClient 实现京东云 CDN 测试控制面。
type fakeJDCloudCDNClient struct {
	domains        []cdnmodel.ListDomainItem    // domains 是完整 fake 域名目录。
	detail         cdnapi.GetDomainDetailResult // detail 是部署目标详情。
	pageError      int                          // pageError 指定返回错误的页码。
	permission     bool                         // permission 表示第一页返回权限错误。
	listCalls      int                          // listCalls 记录分页调用次数。
	setCertificate string                       // setCertificate 是最近绑定的证书 ID。
}

// GetDomainList 返回按请求页码切分的 CDN 域名。
func (f *fakeJDCloudCDNClient) GetDomainList(request *cdnapi.GetDomainListRequest) (*cdnapi.GetDomainListResponse, error) {
	f.listCalls++
	page := 1
	if request.PageNumber != nil {
		page = *request.PageNumber
	}
	if f.pageError == page {
		return nil, errors.New("page failed")
	}
	response := &cdnapi.GetDomainListResponse{RequestID: fmt.Sprintf("request-page-%d", page)}
	if f.permission {
		response.Error = core.ErrorResponse{Code: 403, Status: "Forbidden"}
		return response, nil
	}
	start := (page - 1) * resourcePageSize
	if start > len(f.domains) {
		start = len(f.domains)
	}
	end := start + resourcePageSize
	if end > len(f.domains) {
		end = len(f.domains)
	}
	response.Result = cdnapi.GetDomainListResult{TotalCount: len(f.domains), PageNumber: page, PageSize: resourcePageSize, Domains: append([]cdnmodel.ListDomainItem(nil), f.domains[start:end]...)}
	return response, nil
}

// GetDomainDetail 返回部署目标当前详情。
func (f *fakeJDCloudCDNClient) GetDomainDetail(request *cdnapi.GetDomainDetailRequest) (*cdnapi.GetDomainDetailResponse, error) {
	detail := f.detail
	detail.Domain = request.Domain
	if f.setCertificate != "" {
		detail.HttpType = "https"
		detail.SslCertId = f.setCertificate
	}
	return &cdnapi.GetDomainDetailResponse{RequestID: "request-detail", Result: detail}, nil
}

// SetHttpType 保存精确域名绑定的证书 ID 并返回异步任务。
func (f *fakeJDCloudCDNClient) SetHttpType(request *cdnapi.SetHttpTypeRequest) (*cdnapi.SetHttpTypeResponse, error) {
	if request.Domain != f.detail.Domain || request.SslCertId == nil {
		return nil, errors.New("unexpected deployment target")
	}
	f.setCertificate = *request.SslCertId
	return &cdnapi.SetHttpTypeResponse{RequestID: "request-set", Result: cdnapi.SetHttpTypeResult{TaskId: "task-1"}}, nil
}

// QueryDomainConfigStatus 返回已完成的异步任务状态。
func (f *fakeJDCloudCDNClient) QueryDomainConfigStatus(*cdnapi.QueryDomainConfigStatusRequest) (*cdnapi.QueryDomainConfigStatusResponse, error) {
	return &cdnapi.QueryDomainConfigStatusResponse{RequestID: "request-task", Result: cdnapi.QueryDomainConfigStatusResult{TaskStatus: "success"}}, nil
}

// fakeJDCloudCertificateClient 实现京东云 SSL 测试控制面。
type fakeJDCloudCertificateClient struct {
	certificateID   string // certificateID 是已上传证书 ID。
	certificateName string // certificateName 是指纹派生名称。
	domain          string // domain 是证书覆盖域名。
	uploadCalls     int    // uploadCalls 记录真实上传次数。
}

// UploadCert 保存证书名称并返回稳定证书 ID。
func (f *fakeJDCloudCertificateClient) UploadCert(request *sslapi.UploadCertRequest) (*sslapi.UploadCertResponse, error) {
	f.uploadCalls++
	f.certificateID = "certificate-1"
	f.certificateName = request.CertName
	return &sslapi.UploadCertResponse{RequestID: "request-upload", Result: sslapi.UploadCertResult{CertId: f.certificateID}}, nil
}

// DescribeCert 返回上传后的证书详情。
func (f *fakeJDCloudCertificateClient) DescribeCert(*sslapi.DescribeCertRequest) (*sslapi.DescribeCertResponse, error) {
	return &sslapi.DescribeCertResponse{RequestID: "request-cert-detail", Result: sslapi.DescribeCertResult{CertId: f.certificateID, CertName: f.certificateName, DnsNames: []string{f.domain}}}, nil
}

// DescribeCerts 返回可供幂等复用的证书目录。
func (f *fakeJDCloudCertificateClient) DescribeCerts(*sslapi.DescribeCertsRequest) (*sslapi.DescribeCertsResponse, error) {
	items := []sslmodel.CertListDetail{}
	if f.certificateID != "" {
		items = append(items, sslmodel.CertListDetail{CertId: f.certificateID, CertName: f.certificateName, DnsNames: []string{f.domain}})
	}
	return &sslapi.DescribeCertsResponse{RequestID: "request-cert-list", Result: sslapi.DescribeCertsResult{CertListDetails: items, TotalCount: len(items)}}, nil
}

// TestJDCloudOfflineOrchestration 验证京东云分页、精确资源、上传、异步任务和回读闭环。
func TestJDCloudOfflineOrchestration(t *testing.T) {
	domains := make([]cdnmodel.ListDomainItem, 0, resourcePageSize+1)
	for index := 0; index <= resourcePageSize; index++ {
		domains = append(domains, cdnmodel.ListDomainItem{Domain: fmt.Sprintf("d%02d.example.com", index), Created: fmt.Sprintf("created-%02d", index), Status: "online"})
	}
	cdn := &fakeJDCloudCDNClient{domains: domains, detail: cdnapi.GetDomainDetailResult{Domain: "d00.example.com", Created: "created-00", Status: "online", JumpType: "default"}}
	certificates := &fakeJDCloudCertificateClient{domain: "d00.example.com"}
	provider := newWithClients("access-key", "secret-key", cdn, certificates)
	provider.pollInterval = 0
	certificate := generateJDCloudCertificate(t, "d00.example.com")

	catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY || len(catalog.Resources) != resourcePageSize+1 || cdn.listCalls != 2 {
		t.Fatalf("分页资源发现失败: catalog=%+v calls=%d", catalog, cdn.listCalls)
	}
	resource := catalog.Resources[0]
	resolved, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef)
	if err != nil || resolved.Domain != "d00.example.com" {
		t.Fatalf("精确 targetRef 解析失败: resource=%+v err=%v", resolved, err)
	}
	if err := provider.TestResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef); err != nil {
		t.Fatalf("资源测试失败: %v", err)
	}
	result, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource)
	if err != nil || result.RequestID == "" || cdn.setCertificate != "certificate-1" || certificates.uploadCalls != 1 {
		t.Fatalf("证书部署失败: result=%+v cert=%q uploads=%d err=%v", result, cdn.setCertificate, certificates.uploadCalls, err)
	}
	if err := provider.UploadCertificate(context.Background(), certificate); err != nil || certificates.uploadCalls != 1 {
		t.Fatalf("证书复用失败: uploads=%d err=%v", certificates.uploadCalls, err)
	}
	cdn.detail.Created = "changed"
	if _, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource); err == nil {
		t.Fatal("删除重建后的域名应被拒绝")
	}
	if _, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "stale-target"); err == nil {
		t.Fatal("失效 targetRef 应返回错误")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if catalog := provider.DiscoverResources(canceled, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Error == nil {
		t.Fatalf("取消发现应返回错误: %+v", catalog)
	}
}

// TestJDCloudPartialEmptyPermissionAndConfiguration 验证部分成功、空目录、权限和配置状态。
func TestJDCloudPartialEmptyPermissionAndConfiguration(t *testing.T) {
	domains := make([]cdnmodel.ListDomainItem, resourcePageSize+1)
	for index := range domains {
		domains[index] = cdnmodel.ListDomainItem{Domain: fmt.Sprintf("p%02d.example.com", index), Created: fmt.Sprintf("created-%02d", index), Status: "online"}
	}
	partial := newWithClients("access-key", "secret-key", &fakeJDCloudCDNClient{domains: domains, pageError: 2}, &fakeJDCloudCertificateClient{})
	if catalog := partial.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL || len(catalog.Resources) != resourcePageSize {
		t.Fatalf("部分成功状态不匹配: %+v", catalog)
	}
	empty := newWithClients("access-key", "secret-key", &fakeJDCloudCDNClient{}, &fakeJDCloudCertificateClient{})
	if catalog := empty.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY {
		t.Fatalf("空目录状态不匹配: %+v", catalog)
	}
	permission := newWithClients("access-key", "secret-key", &fakeJDCloudCDNClient{permission: true}, &fakeJDCloudCertificateClient{})
	if catalog := permission.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		t.Fatalf("权限不足状态不匹配: %+v", catalog)
	}
	unconfigured := newWithClients("", "", nil, nil)
	if catalog := unconfigured.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED {
		t.Fatalf("未配置状态不匹配: %+v", catalog)
	}
}

// generateJDCloudCertificate 生成覆盖指定域名的离线 RSA 证书材料。
func generateJDCloudCertificate(t *testing.T, domain string) providers.CertificateMaterial {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	return providers.CertificateMaterial{Name: "jdcloud-test", Domain: domain, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))}
}
