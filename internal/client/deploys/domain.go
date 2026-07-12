package deploys

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/net/idna"
)

const maxDNSNameLength = 253

var feiniuDeploymentMu sync.Mutex

// NormalizeDeploymentDomain validates a deployment domain and returns its canonical and filesystem-safe forms.
func NormalizeDeploymentDomain(rawDomain string) (canonicalDomain, safeName string, err error) {
	domain := strings.TrimSpace(rawDomain)
	if domain == "" {
		return "", "", fmt.Errorf("域名不能为空")
	}
	if strings.HasSuffix(domain, ".") {
		return "", "", fmt.Errorf("域名不能以点结尾: %s", rawDomain)
	}
	for _, r := range domain {
		if unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune(`/\\:'\"`, r) {
			return "", "", fmt.Errorf("域名包含不允许的字符")
		}
	}

	wildcard := strings.HasPrefix(domain, "*.")
	host := domain
	if wildcard {
		host = strings.TrimPrefix(domain, "*.")
	}
	if strings.Contains(host, "*") {
		return "", "", fmt.Errorf("泛域名只能使用开头的 *. 格式")
	}

	asciiHost, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", "", fmt.Errorf("域名格式无效: %w", err)
	}
	asciiHost = strings.ToLower(asciiHost)
	if net.ParseIP(asciiHost) != nil {
		return "", "", fmt.Errorf("部署域名不支持 IP 地址")
	}
	if err := validateDNSHost(asciiHost); err != nil {
		return "", "", err
	}

	if wildcard {
		return "*." + asciiHost, "_." + asciiHost, nil
	}
	return asciiHost, asciiHost, nil
}

// ValidateSafeDomainName validates a previously normalized filesystem-safe domain name.
func ValidateSafeDomainName(safeName string) error {
	canonical := safeName
	if strings.HasPrefix(canonical, "_.") {
		canonical = "*." + strings.TrimPrefix(canonical, "_.")
	}
	_, normalizedSafe, err := NormalizeDeploymentDomain(canonical)
	if err != nil || normalizedSafe != safeName {
		return fmt.Errorf("域名安全名称无效")
	}
	return nil
}

// validateDNSHost validates the length and label syntax of an ASCII DNS hostname.
func validateDNSHost(host string) error {
	if host == "" || len(host) > maxDNSNameLength {
		return fmt.Errorf("域名长度必须在 1-%d 个字符之间", maxDNSNameLength)
	}

	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("域名标签长度必须在 1-63 个字符之间")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("域名标签不能以连字符开头或结尾")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("域名标签包含非法字符")
			}
		}
	}
	return nil
}

// SafeJoinUnderBase joins a relative path while ensuring the result remains under baseDir.
func SafeJoinUnderBase(baseDir string, pathElements ...string) (string, error) {
	if strings.TrimSpace(baseDir) == "" {
		return "", fmt.Errorf("基础目录不能为空")
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("解析基础目录失败: %w", err)
	}
	elements := append([]string{absBase}, pathElements...)
	target := filepath.Clean(filepath.Join(elements...))
	rel, err := filepath.Rel(absBase, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("目标路径超出基础目录")
	}
	return target, nil
}
