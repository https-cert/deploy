package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

var (
	// ErrHTTPServerNotReady 表示本地 HTTP-01 服务尚未成功监听端口。
	ErrHTTPServerNotReady = errors.New("HTTP-01 服务尚未启动")
)

// ChallengeCache 存储 ACME challenge token 和 response 的映射
type ChallengeCache struct {
	// mu 保护 challenge 缓存的并发读写。
	mu sync.RWMutex
	// challenges 保存 token 对应的 challenge 内容和过期时间。
	challenges map[string]*challengeEntry
	// tokenDomains 保存 token 到域名的映射，用于日志记录和调试。
	tokenDomains map[string]string
}

type challengeEntry struct {
	response  string    // challenge response
	expiresAt time.Time // 过期时间
	domain    string    // 关联的域名
}

// HTTPServer HTTP-01 验证服务器
type HTTPServer struct {
	// server 是底层 HTTP 服务实例。
	server *http.Server
	// cache 保存当前等待验证的 HTTP-01 challenge。
	cache *ChallengeCache
	// ready 表示 HTTP 服务已经成功监听配置端口。
	ready         atomic.Bool
	cleanupCtx    context.Context    // cleanupCtx controls the expiry cleanup loop.
	cancelCleanup context.CancelFunc // cancelCleanup stops the expiry cleanup loop.
	cleanupWG     sync.WaitGroup     // cleanupWG waits for the expiry cleanup loop.
	stopOnce      sync.Once          // stopOnce makes Stop idempotent.
	stopErr       error              // stopErr stores the first shutdown result.
}

type healthResponse struct {
	// Status 表示 HTTP-01 验证服务状态。
	Status string `json:"status"`
	// ChallengeCount 表示当前有效 challenge 数量。
	ChallengeCount int `json:"challengeCount"`
	// Time 表示健康检查响应时间。
	Time time.Time `json:"time"`
}

type debugChallengeInfo struct {
	// Domain 是 challenge 关联的域名。
	Domain string `json:"domain"`
	// Token 是脱敏后的 challenge token。
	Token string `json:"token"`
	// ExpiresAt 是 challenge 过期时间。
	ExpiresAt time.Time `json:"expiresAt"`
	// ExpiresInSeconds 是距离过期的剩余秒数。
	ExpiresInSeconds int64 `json:"expiresInSeconds"`
}

type debugChallengesResponse struct {
	// Count 表示返回的有效 challenge 数量。
	Count int `json:"count"`
	// Challenges 是有效 challenge 的脱敏调试信息。
	Challenges []debugChallengeInfo `json:"challenges"`
}

// NewHTTPServer 创建新的 HTTP 服务器
func NewHTTPServer() *HTTPServer {
	mux := http.NewServeMux()
	s := &HTTPServer{
		cache: newChallengeCache(),
	}
	s.cleanupCtx, s.cancelCleanup = context.WithCancel(context.Background())

	// 注册 ACME challenge 处理器
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/debug/challenges", s.handleDebugChallenges)
	mux.HandleFunc("/acme-challenge/", s.handleACMEChallenge)

	cfg := config.GetConfig()
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Server.Port)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 启动清理过期 challenge 的定时任务
	s.cleanupWG.Add(1)
	go s.cleanupExpiredChallenges()

	return s
}

// newChallengeCache 创建空的 challenge 缓存。
func newChallengeCache() *ChallengeCache {
	return &ChallengeCache{
		challenges:   make(map[string]*challengeEntry),
		tokenDomains: make(map[string]string),
	}
}

// Start 启动 HTTP 服务器
func (s *HTTPServer) Start() error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("HTTP 服务器监听失败: %w", err)
	}
	s.ready.Store(true)
	defer s.ready.Store(false)

	if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP 服务器启动失败: %w", err)
	}

	return nil
}

// IsReady 判断 HTTP-01 服务是否已经成功监听端口。
func (s *HTTPServer) IsReady() bool {
	return s != nil && s.ready.Load()
}

// Stop 停止 HTTP 服务器
func (s *HTTPServer) Stop(ctx context.Context) error {
	s.stopOnce.Do(func() {
		s.cancelCleanup()
		s.stopErr = s.server.Shutdown(ctx)
		s.cleanupWG.Wait()
	})
	if s.stopErr == http.ErrServerClosed {
		return nil
	}
	return s.stopErr
}

// handleHealthz 返回 HTTP-01 验证服务健康状态。
func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, healthResponse{
		Status:         "ok",
		ChallengeCount: s.cache.CountActive(),
		Time:           time.Now(),
	})
}

// handleDebugChallenges 返回有效 challenge 的脱敏调试信息。
func (s *HTTPServer) handleDebugChallenges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	challenges := s.cache.DebugChallenges()
	writeJSON(w, http.StatusOK, debugChallengesResponse{
		Count:      len(challenges),
		Challenges: challenges,
	})
}

// handleACMEChallenge 处理 ACME HTTP-01 challenge 请求
func (s *HTTPServer) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 从 URL 中提取 token
	// URL 格式: /acme-challenge/{token}
	token := strings.TrimPrefix(r.URL.Path, "/acme-challenge/")

	if !validChallengeToken(token) {
		http.NotFound(w, r)
		return
	}

	// 从缓存获取 challenge
	response, found := s.cache.Get(token)
	if !found {
		http.NotFound(w, r)
		return
	}

	// 返回 challenge response
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

// writeJSON 输出 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error("写入 JSON 响应失败", "error", err)
	}
}

// SetChallenge 设置 challenge token 和 response，10 分钟后过期。
func (s *HTTPServer) SetChallenge(token, response, domain string) error {
	if !s.IsReady() {
		return ErrHTTPServerNotReady
	}
	if !validChallengeToken(token) || strings.TrimSpace(response) == "" || len(response) > 16*1024 {
		return errors.New("challenge token 或 key authorization 无效")
	}
	s.cache.Set(token, response, domain, time.Minute*10)
	return nil
}

// RemoveChallenge 精确移除 challenge token。
func (s *HTTPServer) RemoveChallenge(token string) error {
	if !s.IsReady() {
		return ErrHTTPServerNotReady
	}
	if !validChallengeToken(token) {
		return errors.New("challenge token 无效")
	}
	s.cache.Delete(token)
	return nil
}

// cleanupExpiredChallenges 定期清理过期的 challenge
func (s *HTTPServer) cleanupExpiredChallenges() {
	defer s.cleanupWG.Done()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.cleanupCtx.Done():
			return
		case <-ticker.C:
			s.cache.CleanExpired()
		}
	}
}

// validChallengeToken validates the URL-safe token format used by ACME HTTP-01.
func validChallengeToken(token string) bool {
	if token == "" || len(token) > 256 || strings.Contains(token, "/") {
		return false
	}
	for _, r := range token {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// ChallengeCache 方法

// Set 设置 challenge，带过期时间
func (c *ChallengeCache) Set(token, response, domain string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.challenges[token] = &challengeEntry{
		response:  response,
		expiresAt: time.Now().Add(ttl),
		domain:    domain,
	}
	c.tokenDomains[token] = domain
}

// Get 获取 challenge response
func (c *ChallengeCache) Get(token string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.challenges[token]
	if !exists {
		return "", false
	}

	// 检查是否过期
	if time.Now().After(entry.expiresAt) {
		return "", false
	}

	return entry.response, true
}

// Delete 删除 challenge
func (c *ChallengeCache) Delete(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.challenges, token)
	delete(c.tokenDomains, token)
}

// CleanExpired 清理所有过期的 challenge
func (c *ChallengeCache) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for token, entry := range c.challenges {
		if now.After(entry.expiresAt) {
			delete(c.challenges, token)
			delete(c.tokenDomains, token)
		}
	}
}

// CountActive 返回当前未过期的 challenge 数量。
func (c *ChallengeCache) CountActive() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, entry := range c.challenges {
		if !now.After(entry.expiresAt) {
			count++
		}
	}
	return count
}

// DebugChallenges 返回当前有效 challenge 的脱敏调试信息。
func (c *ChallengeCache) DebugChallenges() []debugChallengeInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	challenges := make([]debugChallengeInfo, 0, len(c.challenges))
	for token, entry := range c.challenges {
		if now.After(entry.expiresAt) {
			continue
		}

		challenges = append(challenges, debugChallengeInfo{
			Domain:           entry.domain,
			Token:            maskChallengeToken(token),
			ExpiresAt:        entry.expiresAt,
			ExpiresInSeconds: int64(entry.expiresAt.Sub(now).Seconds()),
		})
	}

	sort.Slice(challenges, func(i, j int) bool {
		if challenges[i].Domain == challenges[j].Domain {
			return challenges[i].Token < challenges[j].Token
		}
		return challenges[i].Domain < challenges[j].Domain
	})
	return challenges
}

// maskChallengeToken 对 challenge token 做脱敏处理。
func maskChallengeToken(token string) string {
	if len(token) <= 8 {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]
}

// GetDomain 获取 token 对应的域名
func (c *ChallengeCache) GetDomain(token string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	domain, exists := c.tokenDomains[token]
	return domain, exists
}
