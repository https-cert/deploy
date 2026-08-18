package volcengine

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
	cdnapi "github.com/volcengine/volcengine-go-sdk/service/cdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineerr"
)

// fakeVolcengineCDNClient 实现火山引擎 CDN 测试控制面。
type fakeVolcengineCDNClient struct {
	domains       []*cdnapi.DataForListCdnDomainsOutput // domains 是完整 fake 域名目录。
	listPageError int64                                 // listPageError 指定返回错误的页码。
	listError     error                                 // listError 是第一页读取错误。
	certificateID string                                // certificateID 是已上传证书 ID。
	fingerprint   string                                // fingerprint 是证书 SHA-256 指纹。
	updatedCertID string                                // updatedCertID 是 CDN 当前绑定证书 ID。
	createdAt     int64                                 // createdAt 是精确域名创建时间。
	listCalls     int                                   // listCalls 记录域名分页次数。
	addCalls      int                                   // addCalls 记录证书上传次数。
	updateCalls   int                                   // updateCalls 记录配置更新次数。
}

// ListCdnDomainsWithContext 返回按页切分的 CDN 域名并观察 context。
func (f *fakeVolcengineCDNClient) ListCdnDomainsWithContext(ctx volcengine.Context, input *cdnapi.ListCdnDomainsInput, _ ...request.Option) (*cdnapi.ListCdnDomainsOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.listCalls++
	page := int64(1)
	if input.PageNum != nil {
		page = *input.PageNum
	}
	if f.listError != nil || f.listPageError == page {
		if f.listError != nil {
			return nil, f.listError
		}
		return nil, errors.New("page failed")
	}
	start := int((page - 1) * pageSize)
	if start > len(f.domains) {
		start = len(f.domains)
	}
	end := start + pageSize
	if end > len(f.domains) {
		end = len(f.domains)
	}
	total := int64(len(f.domains))
	return &cdnapi.ListCdnDomainsOutput{Metadata: volcengineMetadata(fmt.Sprintf("request-page-%d", page)), Data: append([]*cdnapi.DataForListCdnDomainsOutput(nil), f.domains[start:end]...), Total: &total}, nil
}

// ListCertInfoWithContext 返回空目录或已上传证书详情。
func (f *fakeVolcengineCDNClient) ListCertInfoWithContext(ctx volcengine.Context, _ *cdnapi.ListCertInfoInput, _ ...request.Option) (*cdnapi.ListCertInfoOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	items := []*cdnapi.CertInfoForListCertInfoOutput{}
	if f.certificateID != "" {
		items = append(items, &cdnapi.CertInfoForListCertInfoOutput{CertId: volcengine.String(f.certificateID), CertFingerprint: &cdnapi.CertFingerprintForListCertInfoOutput{Sha256: volcengine.String(f.fingerprint)}})
	}
	total := int64(len(items))
	return &cdnapi.ListCertInfoOutput{Metadata: volcengineMetadata("request-cert-list"), CertInfo: items, Total: &total}, nil
}

// AddCertificateWithContext 保存证书上传并返回稳定 ID。
func (f *fakeVolcengineCDNClient) AddCertificateWithContext(ctx volcengine.Context, _ *cdnapi.AddCertificateInput, _ ...request.Option) (*cdnapi.AddCertificateOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.addCalls++
	f.certificateID = "certificate-1"
	return &cdnapi.AddCertificateOutput{Metadata: volcengineMetadata("request-upload"), CertId: volcengine.String(f.certificateID)}, nil
}

// DescribeCdnConfigWithContext 返回部署目标当前身份与 HTTPS 配置。
func (f *fakeVolcengineCDNClient) DescribeCdnConfigWithContext(ctx volcengine.Context, input *cdnapi.DescribeCdnConfigInput, _ ...request.Option) (*cdnapi.DescribeCdnConfigOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	configuration := &cdnapi.DomainConfigForDescribeCdnConfigOutput{Domain: input.Domain, CreateTime: volcengine.Int64(f.createdAt), Status: volcengine.String("online")}
	if f.updatedCertID != "" {
		configuration.HTTPS = &cdnapi.HTTPSForDescribeCdnConfigOutput{Switch: volcengine.Bool(true), CertInfo: &cdnapi.CertInfoForDescribeCdnConfigOutput{CertId: volcengine.String(f.updatedCertID)}}
	}
	return &cdnapi.DescribeCdnConfigOutput{Metadata: volcengineMetadata("request-config"), DomainConfig: configuration}, nil
}

// UpdateCdnConfigWithContext 保存精确 CDN 证书绑定。
func (f *fakeVolcengineCDNClient) UpdateCdnConfigWithContext(ctx volcengine.Context, input *cdnapi.UpdateCdnConfigInput, _ ...request.Option) (*cdnapi.UpdateCdnConfigOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.updateCalls++
	f.updatedCertID = stringValue(input.HTTPS.CertInfo.CertId)
	return &cdnapi.UpdateCdnConfigOutput{Metadata: volcengineMetadata("request-update")}, nil
}

// TestVolcengineOfflineOrchestration 验证火山 CDN 分页、精确资源、上传、部署和 context 传播。
func TestVolcengineOfflineOrchestration(t *testing.T) {
	certificate := generateVolcengineCertificate(t, "d000.example.com")
	fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		t.Fatalf("计算测试证书指纹失败: %v", err)
	}
	domains := make([]*cdnapi.DataForListCdnDomainsOutput, 0, pageSize+1)
	for index := 0; index <= pageSize; index++ {
		domain := fmt.Sprintf("d%03d.example.com", index)
		createdAt := int64(1000 + index)
		domains = append(domains, &cdnapi.DataForListCdnDomainsOutput{Domain: &domain, CreateTime: &createdAt, Status: volcengine.String("online"), ServiceRegion: volcengine.String("mainland_china"), HTTPS: volcengine.Bool(true)})
	}
	cdn := &fakeVolcengineCDNClient{domains: domains, fingerprint: fingerprint, createdAt: 1000}
	provider := newWithClients("access-key", "secret-key", "cn-beijing", cdn, nil)

	if ok, err := provider.TestConnection(context.Background()); !ok || err != nil {
		t.Fatalf("连接测试失败: ok=%v err=%v", ok, err)
	}
	catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY || len(catalog.Resources) != pageSize+1 || cdn.listCalls != 2 {
		t.Fatalf("分页资源发现失败: catalog=%+v calls=%d", catalog, cdn.listCalls)
	}
	resource := catalog.Resources[0]
	resolved, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef)
	if err != nil || resolved.Domain != "d000.example.com" {
		t.Fatalf("精确 targetRef 解析失败: resource=%+v err=%v", resolved, err)
	}
	if err := provider.TestResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef); err != nil {
		t.Fatalf("资源测试失败: %v", err)
	}
	result, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource)
	if err != nil || result.RequestID != "request-config" || cdn.addCalls != 1 || cdn.updateCalls != 1 || cdn.updatedCertID != "certificate-1" {
		t.Fatalf("证书部署失败: result=%+v adds=%d updates=%d cert=%q err=%v", result, cdn.addCalls, cdn.updateCalls, cdn.updatedCertID, err)
	}
	if err := provider.UploadCertificate(context.Background(), certificate); err != nil || cdn.addCalls != 1 {
		t.Fatalf("证书复用失败: adds=%d err=%v", cdn.addCalls, err)
	}
	cdn.createdAt = 2000
	if _, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource); err == nil {
		t.Fatal("生命周期变化后的域名应被拒绝")
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

// TestVolcenginePartialEmptyPermissionAndConfiguration 验证部分成功、空目录、权限和配置状态。
func TestVolcenginePartialEmptyPermissionAndConfiguration(t *testing.T) {
	domains := make([]*cdnapi.DataForListCdnDomainsOutput, pageSize+1)
	for index := range domains {
		domain := fmt.Sprintf("p%03d.example.com", index)
		createdAt := int64(index + 1)
		domains[index] = &cdnapi.DataForListCdnDomainsOutput{Domain: &domain, CreateTime: &createdAt, Status: volcengine.String("online")}
	}
	partial := newWithClients("access-key", "secret-key", "cn-beijing", &fakeVolcengineCDNClient{domains: domains, listPageError: 2}, nil)
	if catalog := partial.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL || len(catalog.Resources) != pageSize {
		t.Fatalf("部分成功状态不匹配: %+v", catalog)
	}
	empty := newWithClients("access-key", "secret-key", "cn-beijing", &fakeVolcengineCDNClient{}, nil)
	if catalog := empty.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY {
		t.Fatalf("空目录状态不匹配: %+v", catalog)
	}
	serviceError := volcengineerr.New("AccessDenied", "denied", nil)
	denied := volcengineerr.NewRequestFailure(serviceError, 403, "request-denied")
	permission := newWithClients("access-key", "secret-key", "cn-beijing", &fakeVolcengineCDNClient{listError: denied}, nil)
	if catalog := permission.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		t.Fatalf("权限不足状态不匹配: %+v", catalog)
	}
	unconfigured := newWithClients("", "", "cn-beijing", nil, nil)
	if catalog := unconfigured.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED {
		t.Fatalf("未配置状态不匹配: %+v", catalog)
	}
}

// volcengineMetadata 构造带请求 ID 的火山 SDK 响应元数据。
func volcengineMetadata(requestID string) *response.ResponseMetadata {
	return &response.ResponseMetadata{RequestId: requestID}
}

// generateVolcengineCertificate 生成覆盖指定域名的离线 RSA 证书材料。
func generateVolcengineCertificate(t *testing.T, domain string) providers.CertificateMaterial {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	return providers.CertificateMaterial{Name: "volcengine-test", Domain: domain, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))}
}
