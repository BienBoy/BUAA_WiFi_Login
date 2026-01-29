package discovery

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"io"
	"bytes"

	"github.com/BienBoy/srun/internal/config"
)

// CaptivePortalResult Captive Portal探测结果
type CaptivePortalResult struct {
	ProbeURL   string
	StatusCode int
	Redirected bool
	Location   string
	FinalURL   string
	IsCaptive  bool
	Reason     string
}

// CheckCaptivePortal 检测captive portal
func CheckCaptivePortal(client *http.Client, probeURL string) (*CaptivePortalResult, error) {
	// 不跟随重定向
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Get(probeURL)
	if err != nil {
		return &CaptivePortalResult{
			ProbeURL:  probeURL,
			IsCaptive: false,
			Reason:    fmt.Sprintf("探测失败: %v", err),
		}, nil
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode
	location := resp.Header.Get("Location")
	redirected := (statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308) && location != ""

	if statusCode == 204 {
		return &CaptivePortalResult{
			ProbeURL:   probeURL,
			StatusCode: statusCode,
			Redirected: false,
			FinalURL:   resp.Request.URL.String(),
			IsCaptive:  false,
			Reason:     "status=204 (正常)",
		}, nil
	}

	if redirected {
		return &CaptivePortalResult{
			ProbeURL:   probeURL,
			StatusCode: statusCode,
			Redirected: true,
			Location:   location,
			FinalURL:   resp.Request.URL.String(),
			IsCaptive:  true,
			Reason:     fmt.Sprintf("重定向 %d -> %s", statusCode, location),
		}, nil
	}

    // 非重定向：从响应体提取跳转目标
	// 读一小段即可，避免大 body
	const maxRead = 64 << 10 // 64KB
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	snip := strings.TrimSpace(string(body))
	if len(snip) > 2048 {
		snip = snip[:2048]
	}

	extractedURL, _ := extractRedirectURLFromBody(body)
	if extractedURL != "" {
		return &CaptivePortalResult{
            ProbeURL:   probeURL,
            StatusCode: statusCode,
            Redirected: true,
            Location:   extractedURL,
            FinalURL:   resp.Request.URL.String(),
            IsCaptive:  true,
            Reason:     fmt.Sprintf("重定向 %d -> %s", statusCode, location),
	}, nil
	}

	return &CaptivePortalResult{
		ProbeURL:   probeURL,
		StatusCode: statusCode,
		Redirected: false,
		FinalURL:   resp.Request.URL.String(),
		IsCaptive:  false,
		Reason:     fmt.Sprintf("无重定向"),
	}, nil
}

func extractRedirectURLFromBody(body []byte) (u string, from string) {
	// 1) JS: location.href="..."
	reJS1 := regexp.MustCompile(`(?is)\blocation\.href\s*=\s*['"]([^'"]+)['"]`)
	if m := reJS1.FindSubmatch(body); len(m) == 2 {
		return string(bytes.TrimSpace(m[1])), "js:location.href"
	}

	// 2) JS: window.location="..." 或 location="..."
	reJS2 := regexp.MustCompile(`(?is)\b(?:window\.)?location\s*=\s*['"]([^'"]+)['"]`)
	if m := reJS2.FindSubmatch(body); len(m) == 2 {
		return string(bytes.TrimSpace(m[1])), "js:location"
	}

	// 3) meta refresh: <meta http-equiv="refresh" content="0;url=...">
	reMeta := regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*['"]?refresh['"]?[^>]+content\s*=\s*['"][^'"]*url=([^'"]+)['"]`)
	if m := reMeta.FindSubmatch(body); len(m) == 2 {
		return string(bytes.TrimSpace(m[1])), "meta:refresh"
	}

	// 4) fallback: 找第一个 a href
	reA := regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*['"]([^'"]+)['"]`)
	if m := reA.FindSubmatch(body); len(m) == 2 {
		return string(bytes.TrimSpace(m[1])), "html:a"
	}

	return "", ""
}

// ExtractBaseURL 从 URL 中提取 base_url（scheme + host）
func ExtractBaseURL(urlStr string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("URL 缺少 scheme 或 host")
	}

	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}

// DiscoverParams 自动探测SRun参数
// 如果 baseURL 为空，会从 captive portal 重定向中提取
// 返回探测到的参数、captive portal 结果和可能的错误
func DiscoverParams(client *http.Client, baseURL, probeURL string) (*config.DiscoveredParams, *CaptivePortalResult, error) {
	var cap *CaptivePortalResult
	var err error
	var entryURL string
	var skipCaptiveCheck bool = false

	if baseURL != "" {
		skipCaptiveCheck = true
		entryURL = strings.TrimRight(baseURL, "/") + "/"
	}

	// 根据skipCaptiveCheck决定是否探测
	if skipCaptiveCheck {
		cap = &CaptivePortalResult{
			ProbeURL:  probeURL,
			FinalURL:  entryURL,
			IsCaptive: false,
			Reason:    "skipped (base_url provided)",
		}
	} else {
		cap, err = CheckCaptivePortal(client, probeURL)
		if err != nil {
			return nil, nil, fmt.Errorf("captive portal探测失败: %w", err)
		}

        if !cap.IsCaptive {
            return nil, cap, fmt.Errorf("未检测到 captive portal")
        }

        // 从重定向 URL 中提取 base_url
        if cap.Location != "" {
            baseURL, err = ExtractBaseURL(cap.Location)
        } else if cap.FinalURL != "" {
            baseURL, err = ExtractBaseURL(cap.FinalURL)
        }

        if err != nil || baseURL == "" {
            return nil, cap, fmt.Errorf("无法从重定向 URL 中提取 base_url")
        }

        entryURL = strings.TrimRight(baseURL, "/") + "/"
	}

	// 访问登录页面获取最终URL（可能会重定向）
	finalURL, err := getFinalURL(client, entryURL)
	if err != nil {
		return nil, cap, fmt.Errorf("访问登录页面失败: %w", err)
	}

	// 从URL查询字符串中解析ac_id
	params := parseParamsFromURL(finalURL)

	if !skipCaptiveCheck {
		params.BaseURL = &baseURL
	}

	return params, cap, nil
}

// getFinalURL 访问URL并获取最终URL（跟随重定向）
func getFinalURL(client *http.Client, url string) (string, error) {
	// 允许跟随重定向
	client.CheckRedirect = nil

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 返回最终的URL（可能经过重定向）
	return resp.Request.URL.String(), nil
}

// parseParamsFromURL 从URL查询字符串中解析ac_id
func parseParamsFromURL(urlStr string) *config.DiscoveredParams {
	params := &config.DiscoveredParams{}

	// 从URL查询字符串中提取ac_id
	if val := detectAcIDFromURL(urlStr); val != "" {
		params.AcID = &val
	}

	return params
}

// detectAcIDFromURL 从URL查询字符串中检测ac_id
func detectAcIDFromURL(urlStr string) string {
	// 从查询字符串参数中提取 (ac_id=xxx)
	patterns := []string{
		`[?&]ac_id=(\d+)`,
		`[?&]acid=(\d+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if match := re.FindStringSubmatch(urlStr); len(match) > 1 {
			return match[1]
		}
	}

	return ""
}

// NewHTTPClient 创建HTTP客户端
func NewHTTPClient(timeoutSec float64, verifyTLS bool) *http.Client {
	transport := &http.Transport{}
	if !verifyTLS {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	return &http.Client{
		Timeout:   time.Duration(timeoutSec * float64(time.Second)),
		Transport: transport,
	}
}
