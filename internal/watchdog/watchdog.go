package watchdog

import (
	"fmt"
	"math"
	"time"

	"github.com/BienBoy/srun/internal/config"
	"github.com/BienBoy/srun/internal/protocol"
)

// Watchdog 自动重连守护进程
type Watchdog struct {
	client       *protocol.Client
	config       *config.Config
	pollInterval time.Duration
	maxBackoff   time.Duration
}

// NewWatchdog 创建守护进程
func NewWatchdog(client *protocol.Client, cfg *config.Config) *Watchdog {
	return &Watchdog{
		client:       client,
		config:       cfg,
		pollInterval: time.Duration(cfg.PollInterval * float64(time.Second)),
		maxBackoff:   time.Duration(cfg.MaxBackoff * float64(time.Second)),
	}
}

// Run 运行守护进程
func (w *Watchdog) Run() error {
	fmt.Println("启动自动重连守护进程...")
	fmt.Printf("轮询间隔: %.1f秒\n", w.config.PollInterval)

	backoff := w.pollInterval
	consecutiveFailures := 0

	for {
		// 检查在线状态
		info, err := w.client.RadUserInfo()
		if err != nil {
			fmt.Printf("查询状态失败: %v\n", err)
			consecutiveFailures++
			backoff = w.calculateBackoff(consecutiveFailures)
			time.Sleep(backoff)
			continue
		}

		// 判断是否在线
		if protocol.IsOnline(info) {
			fmt.Printf("[%s] 在线\n", time.Now().Format("2006-01-02 15:04:05"))
			consecutiveFailures = 0
			backoff = w.pollInterval
			time.Sleep(w.pollInterval)
			continue
		}

		// 离线，尝试重新登录
		fmt.Printf("[%s] 离线，尝试重新登录...\n", time.Now().Format("2006-01-02 15:04:05"))

		result, err := w.client.Login(w.config)
		if err != nil {
			fmt.Printf("登录失败: %v\n", err)
			consecutiveFailures++
			backoff = w.calculateBackoff(consecutiveFailures)
			time.Sleep(backoff)
			continue
		}

		// 登录成功
		fmt.Println("✓ 登录成功")
		if msg, ok := result["suc_msg"].(string); ok {
			fmt.Printf("  %s\n", msg)
		}

		consecutiveFailures = 0
		backoff = w.pollInterval
		time.Sleep(w.pollInterval)
	}
}

// calculateBackoff 计算退避时间
func (w *Watchdog) calculateBackoff(failures int) time.Duration {
	// 指数退避: pollInterval * 2^failures
	backoff := time.Duration(float64(w.pollInterval) * math.Pow(2, float64(failures)))

	// 限制最大退避时间
	if backoff > w.maxBackoff {
		backoff = w.maxBackoff
	}

	fmt.Printf("等待 %.1f 秒后重试...\n", backoff.Seconds())
	return backoff
}
