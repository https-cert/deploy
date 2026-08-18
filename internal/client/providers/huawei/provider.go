// Package huawei implements Huawei Cloud SCM, CDN, DCDN, OBS and ELB certificate deployment flows.
package huawei

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	sdkconfig "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	cdnapi "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cdn/v2"
	cdnmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cdn/v2/model"
	cdnregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cdn/v2/region"
	scmapi "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/scm/v3"
	scmmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/scm/v3/model"
	scmregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/scm/v3/region"
)

// contextError 返回调用方上下文的取消或超时状态。
func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

const (
	defaultRegion            = "cn-north-4"
	defaultCertificateRegion = "cn-north-4"
	cdnPageSize              = 1000
	scmPageSize              = 50
	maxPages                 = 100
	maxResources             = 10000
	sdkTimeout               = 30 * time.Second
)

var (
	_             providers.ProviderHandler            = (*Provider)(nil)
	_             providers.DeploymentResourceProvider = (*Provider)(nil)
	regionPattern                                      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)
)

// scmClient 是华为云证书管理闭环所需的最小官方 SDK 接口。
type scmClient interface {
	ListCertificates(request *scmmodel.ListCertificatesRequest) (*scmmodel.ListCertificatesResponse, error)
	ImportCertificate(request *scmmodel.ImportCertificateRequest) (*scmmodel.ImportCertificateResponse, error)
	ShowCertificate(request *scmmodel.ShowCertificateRequest) (*scmmodel.ShowCertificateResponse, error)
}

// cdnClient 是华为云 CDN 和全站加速闭环所需的最小官方 SDK 接口。
type cdnClient interface {
	ListDomains(request *cdnmodel.ListDomainsRequest) (*cdnmodel.ListDomainsResponse, error)
	ShowDomainDetailByName(request *cdnmodel.ShowDomainDetailByNameRequest) (*cdnmodel.ShowDomainDetailByNameResponse, error)
	ShowDomainFullConfig(request *cdnmodel.ShowDomainFullConfigRequest) (*cdnmodel.ShowDomainFullConfigResponse, error)
	UpdateDomainMultiCertificates(request *cdnmodel.UpdateDomainMultiCertificatesRequest) (*cdnmodel.UpdateDomainMultiCertificatesResponse, error)
}

// Provider 保存华为云凭据、地域和各产品官方 SDK 客户端。
type Provider struct {
	accessKey         string               // accessKey 是华为云 Access Key ID。
	secretKey         string               // secretKey 是华为云 Secret Access Key。
	region            string               // region 是默认 OBS 和 ELB 地域。
	certificateRegion string               // certificateRegion 是 SCM 证书中心地域。
	regions           []string             // regions 是参与 OBS 和 ELB 资源发现的地域集合。
	scm               scmClient            // scm 负责证书导入、复用和指纹回读。
	cdn               cdnClient            // cdn 负责 CDN 和全站加速域名控制面。
	elbClients        map[string]elbClient // elbClients 按地域保存 ELB 控制面客户端。
	obsClients        map[string]obsClient // obsClients 按地域保存 OBS 控制面客户端。
}

// New 使用华为云官方 SDK 创建 provider。
func New(accessKey, secretKey, region, certificateRegion string, regions []string) (*Provider, error) {
	accessKey = strings.TrimSpace(accessKey)
	secretKey = strings.TrimSpace(secretKey)
	region = strings.TrimSpace(region)
	if region == "" {
		region = defaultRegion
	}
	certificateRegion = strings.TrimSpace(certificateRegion)
	if certificateRegion == "" {
		certificateRegion = defaultCertificateRegion
	}
	resolvedRegions, err := normalizeRegions(region, regions)
	if err != nil {
		return nil, err
	}

	globalCredential, err := global.NewCredentialsBuilder().WithAk(accessKey).WithSk(secretKey).SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("创建华为云全局凭据失败: %w", err)
	}
	cdnHTTPClient, err := cdnapi.CdnClientBuilder().
		WithRegion(cdnregion.CN_NORTH_1).
		WithCredential(globalCredential).
		WithHttpConfig(sdkconfig.DefaultHttpConfig().WithTimeout(sdkTimeout)).
		SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("创建华为云 CDN 客户端失败: %w", err)
	}

	certificateServiceRegion, err := scmregion.SafeValueOf(certificateRegion)
	if err != nil {
		return nil, fmt.Errorf("华为云 SCM 地域无效: %w", err)
	}
	certificateCredential, err := basic.NewCredentialsBuilder().WithAk(accessKey).WithSk(secretKey).SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("创建华为云 SCM 凭据失败: %w", err)
	}
	scmHTTPClient, err := scmapi.ScmClientBuilder().
		WithRegion(certificateServiceRegion).
		WithCredential(certificateCredential).
		WithHttpConfig(sdkconfig.DefaultHttpConfig().WithTimeout(sdkTimeout)).
		SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("创建华为云 SCM 客户端失败: %w", err)
	}

	elbClients, err := newELBClients(accessKey, secretKey, resolvedRegions)
	if err != nil {
		return nil, err
	}
	obsClients, err := newOBSClients(accessKey, secretKey, resolvedRegions)
	if err != nil {
		return nil, err
	}
	return newWithClients(
		accessKey,
		secretKey,
		region,
		certificateRegion,
		resolvedRegions,
		scmapi.NewScmClient(scmHTTPClient),
		cdnapi.NewCdnClient(cdnHTTPClient),
		elbClients,
		obsClients,
	), nil
}

// newWithClients 创建支持单元测试替身注入的华为云 provider。
func newWithClients(accessKey, secretKey, region, certificateRegion string, regions []string, scm scmClient, cdn cdnClient, elbClients map[string]elbClient, obsClients map[string]obsClient) *Provider {
	return &Provider{
		accessKey:         strings.TrimSpace(accessKey),
		secretKey:         strings.TrimSpace(secretKey),
		region:            strings.TrimSpace(region),
		certificateRegion: strings.TrimSpace(certificateRegion),
		regions:           append([]string(nil), regions...),
		scm:               scm,
		cdn:               cdn,
		elbClients:        elbClients,
		obsClients:        obsClients,
	}
}

// TestConnection 验证凭据可以读取 SCM 证书目录。
func (p *Provider) TestConnection(ctx context.Context) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if err := p.validateCredentials(); err != nil {
		return false, err
	}
	if p.scm == nil {
		return false, providers.NewDeploymentError("华为云 SCM 客户端未初始化", false, "", nil)
	}
	limit := int32(1)
	response, err := p.scm.ListCertificates(&scmmodel.ListCertificatesRequest{Limit: &limit})
	if contextErr := contextError(ctx); contextErr != nil {
		return false, contextErr
	}
	if err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	if response == nil {
		return false, providers.NewDeploymentError("华为云测试连接响应为空", true, "", nil)
	}
	return true, nil
}

// stableCertificateName 根据叶证书 SHA-256 生成满足云端长度约束的稳定名称。
func stableCertificateName(certificatePEM string) string {
	fingerprint, err := providers.LeafCertificateSHA256(certificatePEM)
	if err != nil || len(fingerprint) < 32 {
		return "anssl-certificate"
	}
	return "anssl-" + fingerprint[:32]
}

// leafCertificateSHA1 计算 SCM 详情返回格式对应的叶证书 SHA-1 指纹。
func leafCertificateSHA1(certificatePEM string) (string, error) {
	remaining := []byte(certificatePEM)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		fingerprint := sha1.Sum(certificate.Raw)
		return hex.EncodeToString(fingerprint[:]), nil
	}
	return "", errors.New("未找到 PEM 证书块")
}

// splitCertificateChain 将完整 PEM 拆分为叶证书和剩余证书链。
func splitCertificateChain(certificatePEM string) (string, string, error) {
	remaining := []byte(certificatePEM)
	certificates := make([][]byte, 0)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificates = append(certificates, pem.EncodeToMemory(block))
	}
	if len(certificates) == 0 {
		return "", "", errors.New("未找到 PEM 证书块")
	}
	leaf := string(certificates[0])
	chainBuilder := strings.Builder{}
	for _, certificate := range certificates[1:] {
		chainBuilder.Write(certificate)
	}
	return leaf, chainBuilder.String(), nil
}

// normalizeRegions 归一化并校验需要初始化的地域集合。
func normalizeRegions(primary string, regions []string) ([]string, error) {
	values := append([]string{strings.TrimSpace(primary)}, regions...)
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		region := strings.ToLower(strings.TrimSpace(value))
		if region == "" {
			continue
		}
		if !regionPattern.MatchString(region) {
			return nil, fmt.Errorf("华为云地域格式无效: %s", region)
		}
		if _, exists := seen[region]; exists {
			continue
		}
		seen[region] = struct{}{}
		result = append(result, region)
	}
	if len(result) == 0 {
		return nil, errors.New("华为云地域列表不能为空")
	}
	sort.Strings(result)
	return result, nil
}

// validateCredentials 拒绝空凭据和控制字符。
func (p *Provider) validateCredentials() error {
	if p == nil || strings.TrimSpace(p.accessKey) == "" || strings.TrimSpace(p.secretKey) == "" {
		return providers.NewDeploymentError("华为云 accessKeyId 或 accessKeySecret 未配置", false, "", nil)
	}
	if strings.ContainsAny(p.accessKey+p.secretKey, "\r\n\x00") {
		return providers.NewDeploymentError("华为云访问密钥格式无效", false, "", nil)
	}
	return nil
}

// toDeploymentError 将华为云 SDK 错误转换为统一重试分类。
func toDeploymentError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}
	retryable := false
	var serviceError *sdkerr.ServiceResponseError
	if errors.As(err, &serviceError) {
		code := strings.ToLower(strings.TrimSpace(serviceError.ErrorCode))
		retryable = serviceError.StatusCode == http.StatusTooManyRequests || serviceError.StatusCode >= http.StatusInternalServerError || strings.Contains(code, "throttl") || strings.Contains(code, "timeout") || strings.Contains(code, "internal")
	}
	if obsError, ok := asOBSError(err); ok {
		code := strings.ToLower(strings.TrimSpace(obsError.Code))
		retryable = obsError.StatusCode == http.StatusTooManyRequests || obsError.StatusCode >= http.StatusInternalServerError || strings.Contains(code, "slowdown") || strings.Contains(code, "timeout") || strings.Contains(code, "internal")
	}
	return providers.NewDeploymentError("华为云"+operation+"失败", retryable, requestIDFromError(err), err)
}

// isPermissionDenied 判断华为云错误是否属于认证或授权不足。
func isPermissionDenied(err error) bool {
	var serviceError *sdkerr.ServiceResponseError
	if errors.As(err, &serviceError) {
		code := strings.ToLower(strings.TrimSpace(serviceError.ErrorCode))
		return serviceError.StatusCode == http.StatusUnauthorized || serviceError.StatusCode == http.StatusForbidden || strings.Contains(code, "denied") || strings.Contains(code, "unauthorized") || strings.Contains(code, "forbidden")
	}
	if obsError, ok := asOBSError(err); ok {
		code := strings.ToLower(strings.TrimSpace(obsError.Code))
		return obsError.StatusCode == http.StatusUnauthorized || obsError.StatusCode == http.StatusForbidden || strings.Contains(code, "accessdenied")
	}
	return false
}

// requestIDFromError 提取华为云 SDK 错误中的请求 ID。
func requestIDFromError(err error) string {
	var serviceError *sdkerr.ServiceResponseError
	if errors.As(err, &serviceError) {
		return strings.TrimSpace(serviceError.RequestId)
	}
	if obsError, ok := asOBSError(err); ok {
		return strings.TrimSpace(obsError.RequestId)
	}
	return ""
}

// normalizeFingerprint 统一十六进制指纹的大小写和分隔符。
func normalizeFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.ReplaceAll(strings.ReplaceAll(value, ":", ""), "-", "")
}

// stringPointerValue 安全读取可选字符串。
func stringPointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

// int32PointerValue 安全读取可选 int32。
func int32PointerValue(value *int32) int32 {
	if value == nil {
		return 0
	}
	return *value
}

// int32Pointer 返回 int32 指针。
func int32Pointer(value int32) *int32 {
	return &value
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
