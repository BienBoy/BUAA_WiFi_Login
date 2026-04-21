package protocol

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/BienBoy/srun/internal/config"
	"github.com/BienBoy/srun/internal/crypto"
	"github.com/BienBoy/srun/internal/discovery"
)

// Client SRun客户端
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient 创建客户端
func NewClient(baseURL string, timeoutSec float64, verifyTLS bool) *Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if !verifyTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout:   time.Duration(timeoutSec * float64(time.Second)),
			Transport: transport,
		},
	}
}

// Challenge 挑战值响应
type Challenge struct {
	Challenge string `json:"challenge"`
	ClientIP  string `json:"client_ip"`
}

// GetChallenge 获取挑战值
func (c *Client) GetChallenge(username string) (*Challenge, error) {
	params := url.Values{}
	params.Set("callback", fmt.Sprintf("jQuery1124044069126839574846_%d", time.Now().UnixMilli()))
	params.Set("username", username)
	params.Set("ip", "0.0.0.0")
	params.Set("_", fmt.Sprintf("%d", time.Now().UnixMilli()))

	apiURL := fmt.Sprintf("%s/cgi-bin/get_challenge?%s", c.BaseURL, params.Encode())

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP状态码异常: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	// 去除JSONP包裹
	jsonStr := stripJSONP(string(body))

	var result Challenge
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("解析JSON失败: %w", err)
	}

	if result.Challenge == "" {
		return nil, fmt.Errorf("challenge为空")
	}

	return &result, nil
}

// Login 登录
func (c *Client) Login(cfg *config.Config) (map[string]interface{}, error) {
	result, err := c.loginOnce(cfg)
	if err == nil || !cfg.AutoDiscover || !shouldRetryWithRediscovery(err) {
		return result, err
	}

	if err := c.rediscover(cfg); err != nil {
		return nil, err
	}

	return c.loginOnce(cfg)
}

func (c *Client) loginOnce(cfg *config.Config) (map[string]interface{}, error) {
	// 获取必需参数
	acID, err := cfg.GetAcID()
	if err != nil {
		return nil, err
	}

	n, err := cfg.GetN()
	if err != nil {
		return nil, err
	}

	typ, err := cfg.GetType()
	if err != nil {
		return nil, err
	}

	// 获取challenge和IP
	chall, err := c.GetChallenge(cfg.Username)
	if err != nil {
		return nil, fmt.Errorf("获取challenge失败: %w", err)
	}

	clientIP := chall.ClientIP
	if clientIP == "" {
		return nil, fmt.Errorf("无法获取客户端IP")
	}

	// 构造info参数
	infoJSON, err := crypto.BuildInfo(
		cfg.Username,
		cfg.Password,
		clientIP,
		acID,
		cfg.GetEncVer(),
	)
	if err != nil {
		return nil, fmt.Errorf("构造info失败: %w", err)
	}

	// 加密info
	infoEncoded := crypto.BuildInfoEncoded(infoJSON, chall.Challenge, cfg.GetBase64Alphabet())

	// 获取原始MD5值（用于chksum计算，不带前缀）
	passwordMD5Raw := crypto.GetPasswordMD5Raw(cfg.Password, chall.Challenge)

	// 构造password参数（带{MD5}前缀）
	passwordMD5 := "{MD5}" + passwordMD5Raw

	// 构造chksum（使用原始MD5值）
	chksum := crypto.BuildChecksum(
		chall.Challenge,
		cfg.Username,
		passwordMD5Raw,
		acID,
		clientIP,
		n,
		typ,
		infoEncoded,
	)

	// 提交登录请求
	params := url.Values{}
	params.Set("callback", fmt.Sprintf("jQuery1124044069126839574846_%d", time.Now().UnixMilli()))
	params.Set("action", "login")
	params.Set("username", cfg.Username)
	params.Set("password", passwordMD5)
	params.Set("ac_id", acID)
	params.Set("ip", clientIP)
	params.Set("chksum", chksum)
	params.Set("info", infoEncoded)
	params.Set("n", n)
	params.Set("type", typ)
	params.Set("os", cfg.OSName)
	params.Set("name", cfg.DeviceName)
	params.Set("nas_ip", cfg.NasIP)
	params.Set("double_stack", cfg.GetDoubleStack())
	params.Set("ap_id", cfg.ApID)
	params.Set("ap_ip", cfg.ApIP)
	params.Set("mac", cfg.MAC)
	params.Set("_", fmt.Sprintf("%d", time.Now().UnixMilli()))

	apiURL := fmt.Sprintf("%s/cgi-bin/srun_portal?%s", c.BaseURL, params.Encode())

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("登录请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP状态码异常: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	jsonStr := stripJSONP(string(body))

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("解析JSON失败: %w, 响应内容: %s", err, string(body))
	}

	// 检查登录结果
	if errVal, ok := result["error"]; ok {
		if errStr, ok := errVal.(string); ok && strings.ToLower(errStr) != "ok" {
			errMsg := result["error_msg"]
			return nil, fmt.Errorf("%v", errMsg)
		}
	}

	return result, nil
}

// Logout 登出
func (c *Client) Logout(cfg *config.Config) (map[string]interface{}, error) {
	result, err := c.logoutOnce(cfg)
	if err == nil || !cfg.AutoDiscover || !shouldRetryWithRediscovery(err) {
		return result, err
	}

	if err := c.rediscover(cfg); err != nil {
		return nil, err
	}

	return c.logoutOnce(cfg)
}

func (c *Client) logoutOnce(cfg *config.Config) (map[string]interface{}, error) {
	// 获取必需参数
	acID, err := cfg.GetAcID()
	if err != nil {
		return nil, err
	}

	info, err := c.RadUserInfo()
	if err != nil {
		return nil, fmt.Errorf("获取在线信息失败: %w", err)
	}

	// 提交登出请求
	params := url.Values{}
	params.Set("callback", fmt.Sprintf("jQuery1124044069126839574846_%d", time.Now().UnixMilli()))
	params.Set("action", "logout")
	params.Set("username", extractOnlineUsername(info, cfg.Username))
	params.Set("ac_id", acID)
	params.Set("ip", extractOnlineIP(info))
	params.Set("_", fmt.Sprintf("%d", time.Now().UnixMilli()))

	apiURL := fmt.Sprintf("%s/cgi-bin/srun_portal?%s", c.BaseURL, params.Encode())

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("登出请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP状态码异常: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	jsonStr := stripJSONP(string(body))

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("解析JSON失败: %w, 响应内容: %s", err, string(body))
	}

	// 检查登出结果
	if errVal, ok := result["error"]; ok {
		if errStr, ok := errVal.(string); ok && strings.ToLower(errStr) != "ok" {
			errMsg := result["error_msg"]
			return nil, fmt.Errorf("%v", errMsg)
		}
	}

	return result, nil
}

// RadUserInfo 查询在线信息
func (c *Client) RadUserInfo() (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("callback", fmt.Sprintf("jQuery1124044069126839574846_%d", time.Now().UnixMilli()))
	params.Set("_", fmt.Sprintf("%d", time.Now().UnixMilli()))

	apiURL := fmt.Sprintf("%s/cgi-bin/rad_user_info?%s", c.BaseURL, params.Encode())

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP状态码异常: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	jsonStr := stripJSONP(string(body))

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("解析JSON失败: %w", err)
	}

	return result, nil
}

// stripJSONP 去除JSONP包裹
func stripJSONP(text string) string {
	re := regexp.MustCompile(`^\s*([A-Za-z_]\w*)\((.*)\)\s*;?\s*$`)
	if match := re.FindStringSubmatch(text); len(match) > 2 {
		return strings.TrimSpace(match[2])
	}
	return strings.TrimSpace(text)
}

// IsOnline 判断是否在线
func IsOnline(info map[string]interface{}) bool {
	if err, ok := info["error"].(string); ok && strings.ToLower(err) == "ok" {
		return true
	}
	if online, ok := info["online"]; ok {
		switch v := online.(type) {
		case float64:
			return v == 1
		case string:
			return v == "1" || strings.ToLower(v) == "true"
		case bool:
			return v
		}
	}
	return false
}

func extractOnlineIP(info map[string]interface{}) string {
	for _, key := range []string{"online_ip", "client_ip", "user_ip"} {
		if ip, ok := info[key].(string); ok && ip != "" {
			return ip
		}
	}
	return ""
}

func extractOnlineUsername(info map[string]interface{}, fallback string) string {
	for _, key := range []string{"user_name", "username"} {
		if username, ok := info[key].(string); ok && username != "" {
			return username
		}
	}
	return fallback
}

func (c *Client) rediscover(cfg *config.Config) error {
	client := discovery.NewHTTPClient(cfg.TimeoutSec, cfg.VerifyTLS)
	params, _, err := discovery.DiscoverParams(client, cfg.BaseURL, cfg.ProbeURL)
	if err != nil {
		return fmt.Errorf("重新探测参数失败: %w", err)
	}

	cfg.ApplyDiscovery(params)
	c.BaseURL = cfg.BaseURL
	return nil
}

func shouldRetryWithRediscovery(err error) bool {
	if err == nil {
		return false
	}

	if isCredentialError(err) {
		return false
	}

	return true
}

func isCredentialError(err error) bool {
	text := strings.ToLower(err.Error())

	patterns := []string{
		"password",
		"username",
		"user not",
		"account",
		"认证失败",
		"密码",
		"账号",
		"用户不存在",
		"用户名不存在",
		"密码错误",
		"account_locked",
		"user_must_modify_password",
	}

	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}

	return false
}
