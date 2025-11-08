package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

/*
使用示例

  // GET 请求示例
  resp, err := Execute(RequestOptions{
      Method: GET,
      Path:   "/v1/domains",
      Query: map[string]string{
          "page": "1",
          "size": "10",
      },
  })

  // POST 请求示例
  resp, err := Execute(RequestOptions{
      Method: POST,
      Path:   "/v1/certificates",
      Body: map[string]any{
          "domain": "example.com",
          "type":   "ssl",
      },
      Headers: map[string]string{
          "Authorization": "Bearer your-token",
      },
  })

  // PUT 请求示例
  resp, err := Execute(RequestOptions{
      Method:  PUT,
      Path:    "/v1/certificates/123",
      Body:    updateData,
      Timeout: 60 * time.Second,
  })

  // DELETE 请求示例
  resp, err := Execute(RequestOptions{
      Method: DELETE,
      Path:   "/v1/certificates/123",
  })

  // 使用自定义 Base URL
  resp, err := Execute(RequestOptions{
      Method:  GET,
      Path:    "/api/resource",
      BaseURL: "https://custom-api.example.com",
  })
*/

// RequestOptions HTTP 请求配置选项
type RequestOptions struct {
	Method  string            // HTTP 请求方法
	Path    string            // API 路径 (例如: "/v1/resource")
	Query   map[string]string // URL 查询参数
	Body    any               // 请求体 (将被 JSON 编码)
	Headers map[string]string // 自定义请求头
	Timeout time.Duration     // 请求超时时间 (默认: 30s)
	BaseURL string            // 覆盖默认 Base URL
}

// Response HTTP 响应
type Response struct {
	StatusCode int            // HTTP 状态码
	Body       map[string]any // 响应体
	Headers    http.Header    // 响应头
}

// Execute 执行 RESTful HTTP 请求
func Execute(opts RequestOptions) (*Response, error) {
	// 设置默认超时时间
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}

	// 构建带查询参数的 URL
	fullURL, err := buildURL(opts.BaseURL, opts.Path, opts.Query)
	if err != nil {
		return nil, fmt.Errorf("failed to build URL: %w", err)
	}

	// 准备请求体
	var bodyReader io.Reader
	if opts.Body != nil {
		bodyBytes, err := json.Marshal(opts.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// 创建带上下文的 HTTP 请求
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, opts.Method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 设置默认请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// 设置自定义请求头
	for key, value := range opts.Headers {
		req.Header.Set(key, value)
	}

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// 解析 JSON 响应
	var bodyMap map[string]any
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &bodyMap); err != nil {
			// 如果不是有效的 JSON，返回原始内容
			bodyMap = map[string]any{
				"raw": string(respBody),
			}
		}
	}

	// 创建响应对象
	response := &Response{
		StatusCode: resp.StatusCode,
		Body:       bodyMap,
		Headers:    resp.Header,
	}

	// 检查 HTTP 错误
	if resp.StatusCode >= 400 {
		return response, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return response, nil
}

// buildURL 构建完整的 URL（包含查询参数）
func buildURL(baseURL, path string, query map[string]string) (string, error) {
	// 确保 base URL 不以斜杠结尾
	baseURL = strings.TrimSuffix(baseURL, "/")

	// 确保路径以斜杠开头
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// 解析 base URL
	u, err := url.Parse(baseURL + path)
	if err != nil {
		return "", err
	}

	// 添加查询参数
	if len(query) > 0 {
		q := u.Query()
		for key, value := range query {
			q.Set(key, value)
		}
		u.RawQuery = q.Encode()
	}

	return u.String(), nil
}
