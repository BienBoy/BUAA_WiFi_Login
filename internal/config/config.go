package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/viper"
	"golang.org/x/term"
)

// Config 配置结构
type Config struct {
	// 基本配置
	BaseURL  string `mapstructure:"base_url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	// SRun协议参数
	AcID           *string `mapstructure:"ac_id"`           // 需要探测或配置
	N              string  `mapstructure:"n"`               // 固定值
	Type           string  `mapstructure:"type"`            // 固定值
	DoubleStack    string  `mapstructure:"double_stack"`    // 固定值
	EncVer         string  `mapstructure:"enc_ver"`         // 固定值
	Base64Alphabet string  `mapstructure:"base64_alphabet"` // 固定值

	// 运行参数
	OSName       string  `mapstructure:"os_name"`
	DeviceName   string  `mapstructure:"device_name"`
	TimeoutSec   float64 `mapstructure:"timeout_sec"`
	PollInterval float64 `mapstructure:"poll_interval_sec"`
	MaxBackoff   float64 `mapstructure:"max_backoff_sec"`
	VerifyTLS    bool    `mapstructure:"verify_tls"`

	// 自动探测配置
	AutoDiscover bool   `mapstructure:"auto_discover"`
	ProbeURL     string `mapstructure:"probe_url"`
}

// Load 加载配置
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// 设置配置文件路径
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// 默认配置文件位置：当前工作目录
		v.AddConfigPath(".")
		v.SetConfigName("config")
		v.SetConfigType("json")
	}

	// 环境变量前缀
	v.SetEnvPrefix("SRUN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// 设置默认值
	setDefaults(v)

	// 读取配置文件（可选）
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}
		// 配置文件不存在是正常的，继续使用环境变量和默认值
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}

	return &cfg, nil
}

// setDefaults 设置默认值
func setDefaults(v *viper.Viper) {
	v.SetDefault("base_url","")
	v.SetDefault("username","")
	v.SetDefault("password","")

	// 运行参数
	v.SetDefault("os_name", "Linux")
	v.SetDefault("device_name", "Linux")
	v.SetDefault("timeout_sec", 30.0)
	v.SetDefault("poll_interval_sec", 10.0)
	v.SetDefault("max_backoff_sec", 120.0)
	v.SetDefault("verify_tls", true)

	// 自动探测配置
	v.SetDefault("auto_discover", true)
	v.SetDefault("probe_url", "http://connectivitycheck.gstatic.com/generate_204")

	// SRun协议参数默认值（仅ac_id需要探测）
	v.SetDefault("n", "200")
	v.SetDefault("type", "1")
	v.SetDefault("double_stack", "0")
	v.SetDefault("enc_ver", "srun_bx1")
	v.SetDefault("base64_alphabet", "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA")
}

// Validate 验证配置
func (c *Config) Validate(requirePassword bool) error {
	// BaseURL 可以为空，会自动探测

	// 如果用户名为空，交互式输入
	if c.Username == "" {
		username, err := promptInput("请输入用户名: ")
		if err != nil {
			return fmt.Errorf("读取用户名失败: %w", err)
		}
		c.Username = username
	}

	// 只有需要密码时才提示输入
	if requirePassword && c.Password == "" {
		password, err := promptPassword("请输入密码: ")
		if err != nil {
			return fmt.Errorf("读取密码失败: %w", err)
		}
		c.Password = password
	}

	return nil
}

// NeedsBaseURLDiscovery 检查是否需要探测 base_url
func (c *Config) NeedsBaseURLDiscovery() bool {
	return c.BaseURL == ""
}

// NeedsDiscovery 检查是否需要自动探测
func (c *Config) NeedsDiscovery() bool {
	// 只有ac_id需要自动探测
	return c.AcID == nil
}

// ApplyDiscovery 应用探测结果
func (c *Config) ApplyDiscovery(params *DiscoveredParams) {
	// 应用 base_url
	if params.BaseURL != nil {
		c.BaseURL = *params.BaseURL
	}

	// 应用 ac_id
	if params.AcID != nil {
		c.AcID = params.AcID
	}
}

// GetAcID 获取ac_id（必须已设置）
func (c *Config) GetAcID() (string, error) {
	if c.AcID == nil {
		return "", fmt.Errorf("ac_id 未设置")
	}
	return *c.AcID, nil
}

// GetN 获取n（固定值）
func (c *Config) GetN() (string, error) {
	return c.N, nil
}

// GetType 获取type（固定值）
func (c *Config) GetType() (string, error) {
	return c.Type, nil
}

// GetDoubleStack 获取double_stack（固定值）
func (c *Config) GetDoubleStack() string {
	return c.DoubleStack
}

// GetEncVer 获取enc_ver（固定值）
func (c *Config) GetEncVer() string {
	return c.EncVer
}

// GetBase64Alphabet 获取base64_alphabet（固定值）
func (c *Config) GetBase64Alphabet() *string {
	if c.Base64Alphabet == "" {
		return nil
	}
	return &c.Base64Alphabet
}

// DiscoveredParams 探测到的参数
type DiscoveredParams struct {
	BaseURL *string // 探测到的 base_url
	AcID    *string // 探测到的 ac_id
}

// promptInput 提示用户输入（明文）
func promptInput(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// promptPassword 提示用户输入密码（隐藏输入）
func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	// 读取密码（不回显）
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}

	fmt.Println() // 换行
	return string(bytePassword), nil
}
