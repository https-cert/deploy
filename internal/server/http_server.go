package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

// ChallengeCache 存储 ACME challenge token 和 response 的映射
type ChallengeCache struct {
	mu           sync.RWMutex
	challenges   map[string]*challengeEntry
	tokenDomains map[string]string // token → domain 映射，用于日志记录和调试
}

type challengeEntry struct {
	response  string    // challenge response
	expiresAt time.Time // 过期时间
	domain    string    // 关联的域名
}

// HTTPServer HTTP-01 验证服务器
type HTTPServer struct {
	server *http.Server
	cache  *ChallengeCache
}

// NewHTTPServer 创建新的 HTTP 服务器
func NewHTTPServer() *HTTPServer {
	cache := &ChallengeCache{
		challenges:   make(map[string]*challengeEntry),
		tokenDomains: make(map[string]string),
	}

	mux := http.NewServeMux()
	s := &HTTPServer{
		cache: cache,
	}

	// 注册 ACME challenge 处理器
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
	go s.cleanupExpiredChallenges()

	return s
}

// Start 启动 HTTP 服务器
func (s *HTTPServer) Start() error {
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP 服务器启动失败: %w", err)
	}

	return nil
}

// Stop 停止 HTTP 服务器
func (s *HTTPServer) Stop(ctx context.Context) error {
	logger.Info("正在停止 HTTP-01 验证服务")
	return s.server.Shutdown(ctx)
}

// handleACMEChallenge 处理 ACME HTTP-01 challenge 请求
func (s *HTTPServer) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	// 从 URL 中提取 token
	// URL 格式: /acme-challenge/{token}
	token := strings.TrimPrefix(r.URL.Path, "/acme-challenge/")

	if token == "" {
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

// SetChallenge 设置 challenge token 和 response，10 分钟后过期
func (s *HTTPServer) SetChallenge(token, response, domain string) {
	s.cache.Set(token, response, domain, time.Minute*10)
}

// RemoveChallenge 移除 challenge
func (s *HTTPServer) RemoveChallenge(token string) {
	s.cache.Delete(token)
}

// cleanupExpiredChallenges 定期清理过期的 challenge
func (s *HTTPServer) cleanupExpiredChallenges() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.cache.CleanExpired()
	}
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

// GetDomain 获取 token 对应的域名
func (c *ChallengeCache) GetDomain(token string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	domain, exists := c.tokenDomains[token]
	return domain, exists
}
