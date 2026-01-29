package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/BienBoy/srun/internal/config"
	"github.com/BienBoy/srun/internal/discovery"
	"github.com/BienBoy/srun/internal/protocol"
	"github.com/BienBoy/srun/internal/watchdog"
	"github.com/spf13/cobra"
)

var (
	configPath    string
	noDiscovery   bool
	jsonOutput    bool
	insecure      bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "srun",
		Short: "SRun 深澜认证自动登录工具",
		Long:  `北航校园网自动登录脚本`,
	}

	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "配置文件路径")
	rootCmd.PersistentFlags().BoolVar(&noDiscovery, "no-discovery", false, "禁用自动参数探测")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "输出JSON格式")
	rootCmd.PersistentFlags().BoolVar(&insecure, "insecure", false, "跳过TLS证书验证")

	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(logoutCmd())
	rootCmd.AddCommand(watchCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "登录校园网",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(true) // 需要密码
			if err != nil {
				fmt.Fprintf(os.Stderr, "错误: %v\n", err)
				os.Exit(1)
			}

			client := protocol.NewClient(cfg.BaseURL, cfg.TimeoutSec, cfg.VerifyTLS)

			fmt.Println("正在登录...")
			result, err := client.Login(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "错误: %v\n", err)
				os.Exit(1)
			}

			if jsonOutput {
				printJSON(result)
			} else {
				fmt.Println("✓ 登录成功")
				if msg, ok := result["suc_msg"].(string); ok {
					fmt.Printf("  %s\n", msg)
				}
			}

			return nil
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查询在线状态",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "错误: %v\n", err)
				os.Exit(1)
			}

			client := protocol.NewClient(cfg.BaseURL, cfg.TimeoutSec, cfg.VerifyTLS)

			info, err := client.RadUserInfo()
			if err != nil {
				fmt.Fprintf(os.Stderr, "错误: %v\n", err)
				os.Exit(1)
			}

			if jsonOutput {
				printJSON(info)
			} else {
				printUserInfo(info)
			}

			return nil
		},
	}
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "登出校园网",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(false) // 不需要密码
			if err != nil {
				fmt.Fprintf(os.Stderr, "错误: %v\n", err)
				os.Exit(1)
			}

			client := protocol.NewClient(cfg.BaseURL, cfg.TimeoutSec, cfg.VerifyTLS)

			fmt.Println("正在登出...")
			result, err := client.Logout(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "错误: %v\n", err)
				os.Exit(1)
			}

			if jsonOutput {
				printJSON(result)
			} else {
				fmt.Println("✓ 登出成功")
			}

			return nil
		},
	}
}

func watchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "watch",
		Short: "自动重连守护进程",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(true) // 需要密码
			if err != nil {
				fmt.Fprintf(os.Stderr, "错误: %v\n", err)
				os.Exit(1)
			}

			client := protocol.NewClient(cfg.BaseURL, cfg.TimeoutSec, cfg.VerifyTLS)
			wd := watchdog.NewWatchdog(client, cfg)

			return wd.Run()
		},
	}
}

// loadConfig 加载配置并自动探测参数
func loadConfig(requirePassword bool) (*config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	if err := cfg.Validate(requirePassword); err != nil {
		return nil, err
	}

	// 如果需要探测 base_url 或 ac_id
	if cfg.AutoDiscover && !noDiscovery {
		needsBaseURL := cfg.NeedsBaseURLDiscovery()
		needsAcID := cfg.NeedsDiscovery()

		if needsBaseURL || needsAcID {
			fmt.Println("正在探测参数...")
			client := discovery.NewHTTPClient(cfg.TimeoutSec, cfg.VerifyTLS)

			// 调用探测函数
			params, cap, err := discovery.DiscoverParams(client, cfg.BaseURL, cfg.ProbeURL)
			if err != nil {
				return nil, fmt.Errorf("自动探测失败: %w", err)
			}

			// 应用探测结果
			cfg.ApplyDiscovery(params)

			// 输出探测结果
			if !jsonOutput {
				if needsBaseURL && params.BaseURL != nil {
					fmt.Printf("✓ 探测到服务器: %s\n", *params.BaseURL)
				}
				if needsAcID && params.AcID != nil {
					fmt.Printf("✓ 探测到 ac_id: %s\n", *params.AcID)
				}
				if !needsBaseURL && cap != nil {
					fmt.Printf("✓ 探测完成 (%s)\n", cap.Reason)
				}
			}
		}
	}

	// 验证 base_url 已设置
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base_url 未设置，请配置或启用自动探测")
	}

	// 最终验证必需参数（只需验证ac_id）
	if _, err := cfg.GetAcID(); err != nil {
		return nil, fmt.Errorf("ac_id未设置，请启用自动探测或手动设置")
	}

	return cfg, nil
}

// printJSON 打印JSON
func printJSON(data interface{}) {
	encoder := os.Stdout
	enc := json.NewEncoder(encoder)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

// printUserInfo 打印用户信息
func printUserInfo(info map[string]interface{}) {
	if protocol.IsOnline(info) {
		fmt.Println("✓ 在线")
	} else {
		fmt.Println("ℹ 离线")
	}

	fmt.Println("\n用户信息:")

	// 用户名
	if username, ok := info["user_name"].(string); ok && username != "" {
		fmt.Printf("  用户名: %s\n", username)
	} else if username, ok := info["username"].(string); ok && username != "" {
		fmt.Printf("  用户名: %s\n", username)
	}

	// IP地址
	if ip, ok := info["user_ip"].(string); ok && ip != "" {
		fmt.Printf("  IP地址: %s\n", ip)
	} else if ip, ok := info["online_ip"].(string); ok && ip != "" {
		fmt.Printf("  IP地址: %s\n", ip)
	} else if ip, ok := info["client_ip"].(string); ok && ip != "" {
		fmt.Printf("  IP地址: %s\n", ip)
	}

	// 流量
	if bytes, ok := info["sum_bytes"].(float64); ok {
		gb := bytes / (1024 * 1024 * 1024)
		fmt.Printf("  已用流量: %.2f GB\n", gb)
	}

	// 时长
	if seconds, ok := info["sum_seconds"].(float64); ok {
		hours := seconds / 3600
		fmt.Printf("  在线时长: %.2f 小时\n", hours)
	}

	// 余额
	if wallet, ok := info["wallet"].(float64); ok {
		fmt.Printf("  账户余额: %.2f 元\n", wallet)
	}
}
