# SRun深澜认证自动登录工具

北航校园网自动登录工具，代码由 Claude Code 实现。

## 功能

- 自动登录校园网
- 查询在线状态
- 登出校园网
- 自动重连守护进程
- 自动探测 base_url 和 ac_id 参数

## 快速开始

### 下载

从 Releases 页面下载对应平台的可执行文件：

- **Windows**: `srun-windows-amd64.exe` (64位) 或 `srun-windows-arm64.exe` (ARM)
- **Linux**: `srun-linux-amd64` (64位) 或 `srun-linux-arm64` (ARM64) 或 `srun-linux-armv7` (ARMv7)
- **macOS**: `srun-darwin-amd64` (Intel) 或 `srun-darwin-arm64` (Apple Silicon)

下载后重命名为 `srun`（Linux/macOS）或 `srun.exe`（Windows），并添加执行权限：

```bash
# Linux/macOS
chmod +x srun
```

### 编译（可选）

如果需要自行编译：

```bash
go build -o srun cmd/srun/main.go
```

### 使用

```bash
# 登录
./srun login

# 查询状态
./srun status

# 登出
./srun logout

# 自动重连守护进程
./srun watch

# 输出帮助信息
./srun help
```

## 配置

### 配置方式（优先级从高到低）

1. **环境变量**（前缀 `SRUN_`）
2. **配置文件**（当前目录的 `config.json`）

### 配置文件示例

```json
{
  "base_url": "https://gw.buaa.edu.cn",
  "username": "your_username",
  "password": "your_password"
}
```

### 环境变量

```bash
export SRUN_USERNAME=your_username
export SRUN_PASSWORD=your_password
export SRUN_BASE_URL=https://gw.buaa.edu.cn
```

### 命令行参数

```
--config string      配置文件路径
--no-discovery       禁用自动参数探测
--json               输出 JSON 格式
--insecure           跳过 TLS 证书验证
```

## 配置选项

### 必需参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `username` | 用户名（学号） | 无（不提供则为交互式输入） |
| `password` | 密码 | 无（不提供则为交互式输入） |

### 认证参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `base_url` | 认证服务器地址 | 自动探测（必须离线状态） |
| `ac_id` | 接入点 ID | 自动探测 |
| `n` | 认证参数 n | `200` |
| `type` | 认证类型 | `1` |
| `double_stack` | 双栈参数 | `0` |
| `enc_ver` | 加密版本 | `srun_bx1` |
| `base64_alphabet` | Base64 字母表 | 默认字母表 |

### 运行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `os_name` | 操作系统名称 | `Linux` |
| `device_name` | 设备名称 | `Linux` |
| `timeout_sec` | 请求超时（秒） | `30.0` |
| `poll_interval_sec` | 轮询间隔（秒） | `10.0` |
| `max_backoff_sec` | 最大退避（秒） | `120.0` |
| `verify_tls` | 验证 TLS 证书 | `true` |

### 探测参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `auto_discover` | 启用自动探测 | `true` |
| `probe_url` | 探测 URL | `http://connectivitycheck.gstatic.com/generate_204` |

## 命令

### login

登录校园网。

```bash
./srun login
```

### status

查询在线状态和账户信息。

```bash
./srun status
```

输出示例：
```
✓ 在线

用户信息:
  用户名: 2024xxxx
  IP地址: 10.10.10.10
  已用流量: 1.23 GB
  在线时长: 2.50 小时
  账户余额: 50.00 元
```

### logout

登出校园网。

```bash
./srun logout
```

### watch

自动重连守护进程，检测到离线时自动重新登录。

```bash
./srun watch
```

## 交互式输入

如果未配置用户名或密码，程序会提示输入：

- **用户名**：明文输入
- **密码**：隐藏输入（不回显）

## 示例

### 使用环境变量

```bash
export SRUN_USERNAME=2020xxxx
export SRUN_PASSWORD=your_password
./srun login
```

### 使用配置文件

创建 `config.json`：
```json
{
  "username": "2020xxxx",
  "password": "your_password"
}
```

运行：
```bash
./srun login
```

### 禁用自动探测

```bash
./srun --no-discovery login
```

### JSON 输出

```bash
./srun --json status
```

## 许可证

MIT License
