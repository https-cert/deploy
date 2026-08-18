package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/config"
)

// roundTripFunc 将函数适配为 HTTP RoundTripper。
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip 执行测试提供的 HTTP 回调。
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// TestWaitForContext 验证等待完成和 context 提前取消。
func TestWaitForContext(t *testing.T) {
	if !waitForContext(context.Background(), time.Millisecond) {
		t.Fatal("正常定时等待应返回 true")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForContext(ctx, time.Second) {
		t.Fatal("已取消 context 应立即返回 false")
	}
}

// TestDownloadFileWithRuntime 验证本地下载、鉴权参数、同源重定向和原子替换。
func TestDownloadFileWithRuntime(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("accessKey") != "access-key" {
			http.Error(response, "missing access key", http.StatusUnauthorized)
			return
		}
		if request.URL.Path == "/redirect" {
			http.Redirect(response, request, server.URL+"/archive", http.StatusFound)
			return
		}
		response.Header().Set("Content-Type", "application/octet-stream")
		_, _ = response.Write([]byte("certificate-archive"))
	}))
	defer server.Close()

	runtime := localDownloadRuntime()
	target := filepath.Join(t.TempDir(), "nested", "certificate.tar.gz")
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := DownloadFileWithRuntime(context.Background(), runtime, server.Client(), "access-key", server.URL+"/redirect", target); err != nil {
		t.Fatalf("下载证书归档失败: %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "certificate-archive" {
		t.Fatalf("下载文件内容不匹配: content=%q err=%v", content, err)
	}
}

// TestDownloadFileRejectsUnsafeResponses 验证状态码、内容类型、大小、跨源重定向和取消清理。
func TestDownloadFileRejectsUnsafeResponses(t *testing.T) {
	runtime := localDownloadRuntime()
	tests := []struct {
		name     string         // name 是子测试名称。
		response *http.Response // response 是 fake transport 返回值。
		wantText string         // wantText 是期望错误片段。
	}{
		{name: "错误状态", response: &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader("denied")), Header: make(http.Header)}, wantText: "状态码"},
		{name: "JSON 内容", response: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"error":"denied"}`)), Header: http.Header{"Content-Type": []string{"application/json"}}}, wantText: "不是证书压缩包"},
		{name: "声明大小超限", response: &http.Response{StatusCode: http.StatusOK, ContentLength: maxDownloadSize + 1, Body: io.NopCloser(strings.NewReader("x")), Header: make(http.Header)}, wantText: "超过大小限制"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return test.response, nil
			})}
			target := filepath.Join(t.TempDir(), "archive")
			err := DownloadFileWithRuntime(context.Background(), runtime, client, "key", "https://example.com/archive", target)
			if err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("错误不匹配: err=%v wantText=%q", err, test.wantText)
			}
		})
	}

	targetServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("unexpected"))
	}))
	defer targetServer.Close()
	redirectServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, targetServer.URL+"/archive", http.StatusFound)
	}))
	defer redirectServer.Close()
	if err := DownloadFileWithRuntime(context.Background(), runtime, redirectServer.Client(), "key", redirectServer.URL+"/archive", filepath.Join(t.TempDir(), "archive")); err == nil || !strings.Contains(err.Error(), "跨主机") {
		t.Fatalf("跨源重定向应被拒绝: %v", err)
	}

	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "archive")
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	if err := DownloadFileWithRuntime(canceledContext, runtime, client, "key", "https://example.com/archive", target); err == nil {
		t.Fatal("取消的下载应返回错误")
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("取消后应清理临时文件: entries=%v err=%v", entries, err)
	}
}

// TestDownloadURLValidation 验证下载协议、用户凭据、本地 HTTP 和 origin 比较。
func TestDownloadURLValidation(t *testing.T) {
	tests := []struct {
		name    string          // name 是子测试名称。
		rawURL  string          // rawURL 是待校验地址。
		runtime *config.Runtime // runtime 是环境快照。
		wantErr bool            // wantErr 表示是否期望失败。
	}{
		{name: "HTTPS", rawURL: "https://example.com/archive"},
		{name: "本地 HTTP", rawURL: "http://127.0.0.1:9000/archive", runtime: localDownloadRuntime()},
		{name: "生产 HTTP", rawURL: "http://example.com/archive", wantErr: true},
		{name: "本地非回环 HTTP", rawURL: "http://example.com/archive", runtime: localDownloadRuntime(), wantErr: true},
		{name: "用户凭据", rawURL: "https://user@example.com/archive", wantErr: true},
		{name: "无主机", rawURL: "https:///archive", wantErr: true},
		{name: "错误协议", rawURL: "ftp://example.com/archive", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := url.Parse(test.rawURL)
			if err != nil {
				t.Fatal(err)
			}
			err = validateDownloadURLForRuntime(parsed, test.runtime)
			if (err != nil) != test.wantErr {
				t.Fatalf("URL 校验结果不匹配: err=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
	if err := validateDownloadURL(nil); err == nil {
		t.Fatal("nil URL 应被拒绝")
	}
	if !isLoopbackHost("localhost") || !isLoopbackHost("[::1]") || isLoopbackHost("example.com") {
		t.Fatal("回环地址判断不匹配")
	}
	first, _ := url.Parse("https://EXAMPLE.com/archive")
	same, _ := url.Parse("https://example.com/other")
	different, _ := url.Parse("https://other.example.com/archive")
	if !sameDownloadOrigin(first, same) || sameDownloadOrigin(first, different) || sameDownloadOrigin(nil, same) {
		t.Fatal("下载 origin 比较不匹配")
	}
}

// TestEnsureDownloadContentType 验证内容类型拒绝时保留错误响应预览。
func TestEnsureDownloadContentType(t *testing.T) {
	response := &http.Response{Header: http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader("provider error"))}
	if err := ensureDownloadContentType(response); err == nil {
		t.Fatal("文本响应应被拒绝")
	}
	preview, err := io.ReadAll(response.Body)
	if err != nil || string(preview) != "provider error" {
		t.Fatalf("错误响应预览未恢复: preview=%q err=%v", preview, err)
	}
	response = &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("archive"))}
	if err := ensureDownloadContentType(response); err != nil {
		t.Fatalf("空内容类型不应被拒绝: %v", err)
	}
}

// TestDownloadFileCompatibilityWrapper 验证无 runtime 兼容入口仍执行 HTTPS 下载。
func TestDownloadFileCompatibilityWrapper(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("archive")), Header: make(http.Header)}, nil
	})}
	target := filepath.Join(t.TempDir(), "archive")
	if err := DownloadFile(context.Background(), client, "key", "https://example.com/archive", target); err != nil {
		t.Fatalf("兼容下载入口失败: %v", err)
	}
	if content, err := os.ReadFile(target); err != nil || string(content) != "archive" {
		t.Fatalf("兼容下载内容不匹配: content=%q err=%v", content, err)
	}
}

// localDownloadRuntime 创建允许回环 HTTP 下载的测试运行时。
func localDownloadRuntime() *config.Runtime {
	return &config.Runtime{Config: &config.Configuration{Server: &config.ServerConfig{Env: "local"}}}
}

// TestRoundTripFuncError 验证测试 RoundTripper 可以传播传输错误。
func TestRoundTripFuncError(t *testing.T) {
	want := errors.New("transport error")
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) { return nil, want })}
	err := DownloadFileWithRuntime(context.Background(), nil, client, "key", "https://example.com/archive", filepath.Join(t.TempDir(), "archive"))
	if !errors.Is(err, want) {
		t.Fatalf("传输错误未传播: %v", err)
	}
}
