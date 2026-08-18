package onepanel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

// DiscoverOnePanelWebsiteResources 动态读取全部 1Panel 网站的脱敏目录。
func DiscoverOnePanelWebsiteResources(ctx context.Context) ([]OnePanelWebsiteResource, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, onePanelDiscoveryTimeout)
	defer cancel()

	records, err := loadOnePanelWebsiteRecords(discoveryContext)
	if err != nil {
		return nil, err
	}
	resources := make([]OnePanelWebsiteResource, 0, len(records))
	for _, record := range records {
		resource := record.Resource
		resource.Domains = append([]string(nil), record.Resource.Domains...)
		resources = append(resources, resource)
	}
	return resources, nil
}

// TestOnePanelWebsiteConnection 只读确认 targetRef 对应网站仍存在、正在运行且 HTTPS 配置可访问。
func TestOnePanelWebsiteConnection(ctx context.Context, targetRef string) error {
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		return fmt.Errorf("1Panel 网站 targetRef 不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, onePanelDiscoveryTimeout)
	defer cancel()

	apiURL, apiKey, err := getOnePanelConfig(ctx)
	if err != nil {
		return err
	}
	record, err := findOnePanelWebsiteByTargetRef(discoveryContext, targetRef)
	if err != nil {
		return err
	}
	if isOnePanelWebsiteStopped(record.Resource.Status) {
		return fmt.Errorf("1Panel 网站未运行")
	}
	if _, err := getOnePanelWebsiteHTTPS(discoveryContext, apiURL, apiKey, record.ID); err != nil {
		return fmt.Errorf("读取 1Panel 网站 HTTPS 配置失败: %w", err)
	}
	return nil
}

// listOnePanelWebsiteSummaries 分页读取全部网站，避免单次响应随网站数量无限增长。
func listOnePanelWebsiteSummaries(ctx context.Context, apiURL, apiKey string) ([]onePanelWebsiteSummary, error) {
	websites := make([]onePanelWebsiteSummary, 0)
	for page := 1; page <= onePanelWebsiteMaxPages; page++ {
		requestBody := map[string]any{
			"page":           page,
			"pageSize":       onePanelWebsitePageSize,
			"name":           "",
			"orderBy":        "created_at",
			"order":          "ascending",
			"websiteGroupId": 0,
			"type":           "",
		}
		var pageData onePanelWebsitePage
		if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodPost, onePanelWebsiteSearchPath, requestBody, &pageData); err != nil {
			return nil, fmt.Errorf("读取 1Panel 网站列表失败: %w", err)
		}
		websites = append(websites, pageData.Items...)
		if len(pageData.Items) == 0 || int64(len(websites)) >= pageData.Total {
			return websites, nil
		}
	}
	return nil, fmt.Errorf("1Panel 网站分页超过安全上限")
}

// loadOnePanelWebsiteRecords 读取全部网站及其域名，并用有限并发控制面板压力。
func loadOnePanelWebsiteRecords(ctx context.Context) ([]onePanelWebsiteRecord, error) {
	apiURL, apiKey, err := getOnePanelConfig(ctx)
	if err != nil {
		return nil, err
	}
	websites, err := listOnePanelWebsiteSummaries(ctx, apiURL, apiKey)
	if err != nil {
		return nil, err
	}
	eligibleWebsites := make([]onePanelWebsiteSummary, 0, len(websites))
	for _, website := range websites {
		if !isOnePanelWebsiteCertificateCapable(website.Protocol) {
			continue
		}
		if website.ID == 0 || strings.TrimSpace(website.CreatedAt) == "" {
			return nil, fmt.Errorf("1Panel 网站缺少生成稳定引用所需的身份字段")
		}
		eligibleWebsites = append(eligibleWebsites, website)
	}
	if len(eligibleWebsites) == 0 {
		return nil, nil
	}

	workerCount := onePanelWebsiteDomainWorkers
	if len(eligibleWebsites) < workerCount {
		workerCount = len(eligibleWebsites)
	}
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type websiteJob struct {
		Index   int                    // Index 是结果数组中的稳定位置。
		Website onePanelWebsiteSummary // Website 是待加载域名的网站。
	}
	jobs := make(chan websiteJob)
	records := make([]onePanelWebsiteRecord, len(eligibleWebsites))
	valid := make([]bool, len(eligibleWebsites))
	errorChannel := make(chan error, 1)
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for job := range jobs {
				domains, loadErr := loadOnePanelWebsiteDomains(workerContext, apiURL, apiKey, job.Website)
				if loadErr != nil {
					select {
					case errorChannel <- loadErr:
						cancel()
					default:
					}
					continue
				}
				if len(domains) == 0 {
					continue
				}
				primaryDomain := normalizeOnePanelDomain(job.Website.PrimaryDomain)
				if primaryDomain == "" {
					primaryDomain = domains[0]
				}
				label := strings.TrimSpace(job.Website.Alias)
				if label == "" {
					label = primaryDomain
				}
				records[job.Index] = onePanelWebsiteRecord{
					ID: job.Website.ID,
					Resource: OnePanelWebsiteResource{
						TargetRef: buildOnePanelWebsiteTargetRef(apiURL, job.Website),
						Label:     label,
						Domain:    primaryDomain,
						Domains:   domains,
						Protocol:  normalizeOnePanelWebsiteProtocol(job.Website.Protocol),
						Status:    normalizeOnePanelWebsiteStatus(job.Website.Status),
					},
				}
				valid[job.Index] = true
			}
		}()
	}
sendJobs:
	for index, website := range eligibleWebsites {
		select {
		case jobs <- websiteJob{Index: index, Website: website}:
		case <-workerContext.Done():
			break sendJobs
		}
	}
	close(jobs)
	waitGroup.Wait()
	select {
	case loadErr := <-errorChannel:
		return nil, loadErr
	default:
	}

	filtered := make([]onePanelWebsiteRecord, 0, len(records))
	for index, record := range records {
		if valid[index] {
			filtered = append(filtered, record)
		}
	}
	return filtered, nil
}

// loadOnePanelWebsiteDomains 读取一个网站的域名并进行规范化、去重和排序。
func loadOnePanelWebsiteDomains(ctx context.Context, apiURL, apiKey string, website onePanelWebsiteSummary) ([]string, error) {
	var domainRecords []onePanelWebsiteDomain
	endpoint := fmt.Sprintf(onePanelWebsiteDomainsPath, website.ID)
	if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodGet, endpoint, nil, &domainRecords); err != nil {
		return nil, fmt.Errorf("读取 1Panel 网站域名失败: %w", err)
	}
	domains := make([]string, 0, len(domainRecords)+1)
	seen := make(map[string]struct{}, len(domainRecords)+1)
	appendDomain := func(raw string) {
		domain := normalizeOnePanelDomain(raw)
		if domain == "" {
			return
		}
		if _, exists := seen[domain]; exists {
			return
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	appendDomain(website.PrimaryDomain)
	for _, domainRecord := range domainRecords {
		appendDomain(domainRecord.Domain)
	}
	sort.Strings(domains)
	return domains, nil
}

// normalizeOnePanelDomain 将面板域名规范化为不带端口的小写 ASCII 主机名或 IP。
func normalizeOnePanelDomain(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		value = strings.TrimPrefix(value, "*.")
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
			value = parsed.Host
		}
	}
	if parsed, err := url.Parse("//" + value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		if wildcard {
			return ""
		}
		return ip.String()
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return ""
	}
	normalized := strings.ToLower(strings.TrimSuffix(ascii, "."))
	if wildcard && normalized != "" {
		return "*." + normalized
	}
	return normalized
}

// buildOnePanelWebsiteTargetRef 根据实例、网站身份和创建时间生成稳定的不透明引用。
func buildOnePanelWebsiteTargetRef(apiURL string, website onePanelWebsiteSummary) string {
	identity := strings.Join([]string{
		onePanelWebsiteResourceProvider,
		"EXECUTE_BUSINES_ANSSL_CLI_1PANEL_WEBSITE_CERT",
		normalizeOnePanelOrigin(apiURL),
		strconv.FormatUint(website.ID, 10),
		strings.TrimSpace(website.CreatedAt),
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return onePanelWebsiteTargetRefPrefix + hex.EncodeToString(digest[:12])
}

// normalizeOnePanelOrigin 规范化仅用于本地哈希的面板来源，不返回或记录该值。
func normalizeOnePanelOrigin(apiURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil {
		return strings.ToLower(strings.TrimRight(strings.TrimSpace(apiURL), "/"))
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	} else {
		parsed.Host = hostname
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/")
}

// findOnePanelWebsiteByTargetRef 重新发现网站并要求 targetRef 唯一匹配。
func findOnePanelWebsiteByTargetRef(ctx context.Context, targetRef string) (*onePanelWebsiteRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, onePanelDiscoveryTimeout)
	defer cancel()

	records, err := loadOnePanelWebsiteRecords(discoveryContext)
	if err != nil {
		return nil, err
	}
	var matched *onePanelWebsiteRecord
	for index := range records {
		if records[index].Resource.TargetRef != targetRef {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("1Panel 网站 targetRef 不唯一，请重新配置部署目标")
		}
		record := records[index]
		matched = &record
	}
	if matched == nil {
		return nil, fmt.Errorf("1Panel 网站不存在或已重新创建，请重新配置部署目标")
	}
	return matched, nil
}

// normalizeOnePanelWebsiteProtocol 只保留可通过 HTTPS 接口部署证书的网站协议。
func normalizeOnePanelWebsiteProtocol(protocol string) string {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case onePanelWebsiteProtocolHTTP:
		return onePanelWebsiteProtocolHTTP
	case onePanelWebsiteProtocolHTTPS:
		return onePanelWebsiteProtocolHTTPS
	default:
		return ""
	}
}

// isOnePanelWebsiteCertificateCapable 判断网站是否为支持 HTTPS 证书部署的 HTTP 服务。
func isOnePanelWebsiteCertificateCapable(protocol string) bool {
	return normalizeOnePanelWebsiteProtocol(protocol) != ""
}

// normalizeOnePanelWebsiteStatus 只暴露网页选择器需要的稳定运行状态。
func normalizeOnePanelWebsiteStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case strings.ToLower(onePanelWebsiteStatusRunning):
		return onePanelWebsiteStatusRunning
	case strings.ToLower(onePanelWebsiteStatusStopped):
		return onePanelWebsiteStatusStopped
	default:
		return ""
	}
}

// isOnePanelWebsiteStopped 仅在面板明确报告停止时阻止连接测试或证书部署。
func isOnePanelWebsiteStopped(status string) bool {
	return normalizeOnePanelWebsiteStatus(status) == onePanelWebsiteStatusStopped
}
