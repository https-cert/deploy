package aliyun

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
)

// newSignedOSSCnameAPI 创建生产 OSS CNAME 适配器。
func newSignedOSSCnameAPI(accessKeyID, accessKeySecret string, httpClient ossHTTPClient) ossCnameAPI {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &signedOSSCnameAPI{
		AccessKeyID:     strings.TrimSpace(accessKeyID),
		AccessKeySecret: strings.TrimSpace(accessKeySecret),
		HTTPClient:      httpClient,
		Now:             time.Now,
	}
}

// ListBuckets 查询当前凭据可见的全部 OSS Bucket。
func (a *signedOSSCnameAPI) ListBuckets(ctx context.Context) ([]ossBucketRecord, error) {
	if a == nil || a.HTTPClient == nil || strings.TrimSpace(a.AccessKeyID) == "" || strings.TrimSpace(a.AccessKeySecret) == "" {
		return nil, &cloudAPIError{Message: "OSS Bucket 目录客户端未初始化"}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://oss.aliyuncs.com/", nil)
	if err != nil {
		return nil, &cloudAPIError{Message: "OSS Bucket 目录请求构造失败", Cause: err}
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	date := now.Format(http.TimeFormat)
	request.Header.Set("Date", date)
	request.Header.Set("Authorization", ossAuthorization(a.AccessKeyID, a.AccessKeySecret, http.MethodGet, "", "", date, "/"))
	response, err := a.HTTPClient.Do(request)
	if err != nil {
		return nil, &cloudAPIError{Message: "OSS Bucket 目录网络请求失败", Cause: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxOSSResponseBodySize+1))
	if err != nil || len(body) > maxOSSResponseBodySize {
		return nil, &cloudAPIError{StatusCode: response.StatusCode, RequestID: ossRequestID(response.Header), Message: "OSS Bucket 目录响应读取失败", Cause: err}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var responseError ossErrorXML
		_ = xml.Unmarshal(body, &responseError)
		return nil, &cloudAPIError{
			StatusCode: response.StatusCode,
			Code:       strings.TrimSpace(responseError.Code),
			RequestID:  firstNonEmpty(ossRequestID(response.Header), responseError.RequestID),
			Message:    "OSS Bucket 目录请求失败",
		}
	}
	var decoded ossListBucketsResultXML
	if err := xml.Unmarshal(body, &decoded); err != nil {
		return nil, &cloudAPIError{RequestID: ossRequestID(response.Header), Message: "OSS Bucket 目录响应格式异常", Cause: err}
	}
	result := make([]ossBucketRecord, 0, len(decoded.Buckets))
	for _, bucket := range decoded.Buckets {
		region := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(bucket.Location)), "oss-")
		if strings.TrimSpace(bucket.Name) == "" || region == "" {
			continue
		}
		result = append(result, ossBucketRecord{Name: strings.TrimSpace(bucket.Name), Region: region, CreatedAt: strings.TrimSpace(bucket.CreationDate)})
	}
	return result, nil
}

// ListCname 查询一个 Bucket 的 CNAME 列表并保留响应 request ID。
func (a *signedOSSCnameAPI) ListCname(ctx context.Context, target providers.DeploymentResource) (ossCnameListResult, error) {
	body, requestID, err := a.execute(ctx, http.MethodGet, target, "cname", nil)
	if err != nil {
		return ossCnameListResult{}, err
	}
	var decoded ossListCnameResultXML
	if err := xml.Unmarshal(body, &decoded); err != nil {
		return ossCnameListResult{}, &cloudAPIError{
			RequestID: requestID,
			Message:   "OSS ListCname 响应格式异常",
			Cause:     err,
		}
	}
	records := make([]ossCnameRecord, 0, len(decoded.Cnames))
	for _, cname := range decoded.Cnames {
		records = append(records, ossCnameRecord{
			Domain: cname.Domain,
			Status: cname.Status,
			Certificate: ossCnameCertificate{
				CertificateID: cname.Certificate.CertificateID,
				Fingerprint:   cname.Certificate.Fingerprint,
				Status:        cname.Certificate.Status,
			},
		})
	}
	return ossCnameListResult{
		Bucket:    decoded.Bucket,
		Records:   records,
		RequestID: requestID,
	}, nil
}

// PutCname 通过 OSS CNAME API 更新一个自定义域名的证书配置。
func (a *signedOSSCnameAPI) PutCname(ctx context.Context, request ossCnamePutRequest) (ossCnamePutResult, error) {
	configuration := ossCertificateConfigurationXML{
		Certificate:    request.CertificatePEM,
		PrivateKey:     request.PrivateKeyPEM,
		PreviousCertID: strings.TrimSpace(request.PreviousCertificateID),
	}
	if request.Force {
		force := true
		configuration.Force = &force
	}
	payload, err := xml.Marshal(ossBucketCnameConfigurationXML{
		Cname: ossCnameXML{
			Domain:                   request.Target.Domain,
			CertificateConfiguration: configuration,
		},
	})
	if err != nil {
		return ossCnamePutResult{}, &cloudAPIError{Message: "OSS PutCname 请求编码失败", Cause: err}
	}
	_, requestID, err := a.execute(ctx, http.MethodPost, request.Target, "cname&comp=add", payload)
	if err != nil {
		return ossCnamePutResult{}, err
	}
	return ossCnamePutResult{RequestID: requestID}, nil
}

// execute 构造、签名并发送一条精确 Bucket CNAME 请求。
func (a *signedOSSCnameAPI) execute(ctx context.Context, method string, target providers.DeploymentResource, rawQuery string, payload []byte) ([]byte, string, error) {
	if a == nil || a.HTTPClient == nil {
		return nil, "", &cloudAPIError{Message: "OSS CNAME 客户端未初始化"}
	}
	if strings.TrimSpace(a.AccessKeyID) == "" || strings.TrimSpace(a.AccessKeySecret) == "" {
		return nil, "", &cloudAPIError{Message: "OSS CNAME 访问凭据不完整"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	requestURL, canonicalResource, err := buildOSSRequestURL(target, rawQuery)
	if err != nil {
		return nil, "", &cloudAPIError{Message: "OSS CNAME endpoint 配置无效", Cause: err}
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(payload))
	if err != nil {
		return nil, "", &cloudAPIError{Message: "OSS CNAME 请求构造失败", Cause: err}
	}

	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	date := now.Format(http.TimeFormat)
	contentType := "application/xml"
	contentMD5 := ""
	if len(payload) > 0 {
		digest := md5.Sum(payload)
		contentMD5 = base64.StdEncoding.EncodeToString(digest[:])
		request.Header.Set("Content-MD5", contentMD5)
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Date", date)
	request.Header.Set("Authorization", ossAuthorization(a.AccessKeyID, a.AccessKeySecret, method, contentMD5, contentType, date, canonicalResource))

	response, err := a.HTTPClient.Do(request)
	if err != nil {
		return nil, "", &cloudAPIError{Message: "OSS CNAME 网络请求失败", Cause: err}
	}
	defer response.Body.Close()
	requestIDFromHeader := ossRequestID(response.Header)
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxOSSResponseBodySize+1))
	if err != nil {
		return nil, requestIDFromHeader, &cloudAPIError{
			StatusCode: response.StatusCode,
			RequestID:  requestIDFromHeader,
			Message:    "OSS CNAME 响应读取失败",
			Cause:      err,
		}
	}
	if len(responseBody) > maxOSSResponseBodySize {
		return nil, requestIDFromHeader, &cloudAPIError{
			StatusCode: response.StatusCode,
			RequestID:  requestIDFromHeader,
			Message:    "OSS CNAME 响应过大",
		}
	}
	requestID := requestIDFromHeader
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var responseError ossErrorXML
		_ = xml.Unmarshal(responseBody, &responseError)
		requestID = firstNonEmpty(requestID, responseError.RequestID)
		return nil, requestID, &cloudAPIError{
			StatusCode: response.StatusCode,
			Code:       strings.TrimSpace(responseError.Code),
			RequestID:  requestID,
			Message:    "OSS CNAME API 请求失败",
		}
	}
	return responseBody, requestID, nil
}

// ossRequestID 以大小写不敏感的方式读取 OSS 请求编号头。
func ossRequestID(headers http.Header) string {
	for key, values := range headers {
		if !strings.EqualFold(key, "x-oss-request-id") || len(values) == 0 {
			continue
		}
		if requestID := strings.TrimSpace(values[0]); requestID != "" {
			return requestID
		}
	}
	return ""
}

// buildOSSRequestURL 创建虚拟主机形式的 OSS URL 和签名所需的 canonical resource。
func buildOSSRequestURL(target providers.DeploymentResource, rawQuery string) (string, string, error) {
	endpoint := strings.TrimSpace(target.Endpoint)
	if endpoint == "" {
		region := strings.TrimSpace(target.Region)
		if region == "" {
			return "", "", fmt.Errorf("缺少 OSS region")
		}
		endpoint = "https://oss-" + region + ".aliyuncs.com"
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(parsedEndpoint.Scheme, "https") || parsedEndpoint.Host == "" {
		return "", "", fmt.Errorf("OSS endpoint 必须是 HTTPS origin")
	}
	if parsedEndpoint.User != nil || parsedEndpoint.Path != "" || parsedEndpoint.RawQuery != "" || parsedEndpoint.Fragment != "" {
		return "", "", fmt.Errorf("OSS endpoint 包含不允许的附加部分")
	}
	bucket := strings.TrimSpace(target.Bucket)
	if bucket == "" {
		return "", "", fmt.Errorf("缺少 OSS Bucket")
	}
	lowerHost := strings.ToLower(parsedEndpoint.Hostname())
	if !strings.HasPrefix(lowerHost, strings.ToLower(bucket)+".") {
		parsedEndpoint.Host = bucket + "." + parsedEndpoint.Host
	}
	parsedEndpoint.Path = "/"
	parsedEndpoint.RawQuery = rawQuery
	return parsedEndpoint.String(), "/" + bucket + "/?" + rawQuery, nil
}

// ossAuthorization 生成 OSS Signature V1 Authorization 头。
func ossAuthorization(accessKeyID, accessKeySecret, method, contentMD5, contentType, date, canonicalResource string) string {
	stringToSign := strings.Join([]string{method, contentMD5, contentType, date, canonicalResource}, "\n")
	mac := hmac.New(sha1.New, []byte(accessKeySecret))
	_, _ = mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return "OSS " + accessKeyID + ":" + signature
}
