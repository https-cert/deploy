package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/https-cert/deploy/pb/deployPB"
	"golang.org/x/net/idna"
)

// BuildTargetRef 使用稳定资源身份生成不透明引用。
func BuildTargetRef(provider string, business deployPB.ExecuteBusinesType, identityParts ...string) string {
	parts := make([]string, 0, len(identityParts)+2)
	parts = append(parts, strings.ToLower(strings.TrimSpace(provider)), BusinessRefName(business))
	for _, part := range identityParts {
		parts = append(parts, strings.ToLower(strings.TrimSpace(part)))
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%s-%s-%s", parts[0], parts[1], hex.EncodeToString(digest[:12]))
}

// StableDomainIdentity 优先使用云端稳定 ID；缺少 ID 时要求域名和创建时间共同标识资源生命周期。
func StableDomainIdentity(stableID, normalizedDomain, createdAt string) (string, bool) {
	stableID = strings.TrimSpace(stableID)
	if stableID != "" {
		return stableID, true
	}
	normalizedDomain = strings.TrimSpace(normalizedDomain)
	createdAt = strings.TrimSpace(createdAt)
	if normalizedDomain == "" || createdAt == "" {
		return "", false
	}
	return normalizedDomain + "\x00" + createdAt, true
}

// BusinessRefName 返回 targetRef 使用的简短稳定业务名。
func BusinessRefName(business deployPB.ExecuteBusinesType) string {
	name := strings.ToLower(strings.TrimPrefix(business.String(), "EXECUTE_BUSINES_"))
	return strings.ReplaceAll(name, "_", "-")
}

// NormalizeDomain 将云 API 返回的域名规范化为小写 ASCII DNS 名称。
func NormalizeDomain(rawDomain string) (string, error) {
	domain := strings.TrimSpace(rawDomain)
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	domain = strings.TrimSuffix(strings.Trim(domain, "[]"), ".")
	wildcard := strings.HasPrefix(domain, "*.")
	if wildcard {
		domain = strings.TrimPrefix(domain, "*.")
	}
	if domain == "" || strings.ContainsAny(domain, "/?#@:") || strings.Contains(domain, "*") {
		return "", fmt.Errorf("域名格式无效")
	}
	asciiDomain, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("域名规范化失败: %w", err)
	}
	asciiDomain = strings.ToLower(strings.TrimSuffix(asciiDomain, "."))
	if wildcard {
		return "*." + asciiDomain, nil
	}
	return asciiDomain, nil
}

// NormalizeDomains 规范化、去重并稳定排序域名集合。
func NormalizeDomains(rawDomains ...string) []string {
	seen := make(map[string]struct{}, len(rawDomains))
	result := make([]string, 0, len(rawDomains))
	for _, rawDomain := range rawDomains {
		domain, err := NormalizeDomain(rawDomain)
		if err != nil {
			continue
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	sort.Strings(result)
	return result
}

// FindResourceByTargetRef 要求目录中只有一个资源匹配引用。
func FindResourceByTargetRef(resources []DeploymentResource, targetRef string) (DeploymentResource, error) {
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		return DeploymentResource{}, fmt.Errorf("targetRef 不能为空")
	}
	var matched *DeploymentResource
	for index := range resources {
		if resources[index].TargetRef != targetRef {
			continue
		}
		if matched != nil {
			return DeploymentResource{}, fmt.Errorf("targetRef 匹配多个资源")
		}
		resource := resources[index]
		matched = &resource
	}
	if matched == nil {
		return DeploymentResource{}, fmt.Errorf("资源已失效，请删除后重新关联")
	}
	return *matched, nil
}

// EnsureResourceReady 拒绝不可执行的资源状态。
func EnsureResourceReady(resource DeploymentResource) error {
	if resource.Availability != deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY {
		return fmt.Errorf("资源当前不可部署")
	}
	return nil
}
