# 参数探测逻辑

## 入口

| 位置 | 作用 |
| --- | --- |
| `cmd/srun/main.go` 的 `loadConfig` | 决定是否执行自动探测 |
| `internal/discovery/discovery.go` 的 `DiscoverParams` | 执行整套探测流程 |
| `internal/config/config.go` 的 `ApplyDiscovery` | 把探测结果写回运行配置 |
| `internal/protocol/protocol.go` 的 `Login` | 使用探测结果发起登录请求 |

## 触发条件

| 条件 | 是否探测 |
| --- | --- |
| `auto_discover=true` 且未传 `--no-discovery`，并且缺少 `base_url` 或 `ac_id` | 是 |
| 已手动配置 `base_url` 和 `ac_id` | 否 |
| 传了 `--no-discovery` | 否 |

说明

启动时只看关键入口参数。若 `base_url` 和 `ac_id` 都已配置，就先直接使用用户配置，不主动探测。若登录或登出失败，且错误不像账号或密码错误，会补做一次重新探测，再重试一次。重新探测时会把 `ac_id`、`nas_ip`、`ap_id`、`ap_ip`、`mac`、`theme` 一起刷新。

## 总流程

| 步骤 | 输入 | 动作 | 输出 |
| --- | --- | --- | --- |
| 1 | 配置中的 `base_url`、`ac_id` | 若两者都存在，直接跳过启动探测 | 使用用户配置继续执行 |
| 2 | 配置中的 `probe_url` | 若缺少 `base_url` 或 `ac_id`，请求探针地址，识别 portal 跳转 | portal 入口 URL |
| 3 | portal 入口 URL | 提取协议和主机 | `base_url` |
| 4 | `base_url/` | 跟随重定向，必要时继续解析 HTML/JS 跳转 | 最终登录页 URL |
| 5 | 最终登录页 URL | 从查询串提取参数 | `ac_id`、`nas_ip`、`ap_id`、`ap_ip`、`mac`、`theme` |
| 6 | 登录或登出失败 | 若错误不像凭据错误，重新探测并重试一次 | 刷新后的参数集 |

## 步骤 1 和步骤 2

### 情况 A

配置里已经有 `base_url`

直接使用它，跳过 captive portal 检测。

### 情况 B

配置里没有 `base_url`

先请求 `probe_url`，默认值是 `http://connectivitycheck.gstatic.com/generate_204`。

这一步关闭自动跟随重定向，只看第一跳结果。

识别顺序如下。

| 优先级 | 来源 | 识别方式 |
| --- | --- | --- |
| 1 | HTTP 重定向 | 响应码是 `301/302/303/307/308`，且 `Location` 非空 |
| 2 | JS 跳转 | 匹配 `location.href=...` |
| 3 | JS 跳转 | 匹配 `window.location=...` 或 `location=...` |
| 4 | HTML 跳转 | 匹配 `meta refresh` |
| 5 | 兜底 | 取第一个 `<a href>` |

只读取响应体前 64KB。

若这一步拿到了入口 URL，就从中提取 `scheme + host` 作为 `base_url`。例如当前北航环境会得到 `https://gw.buaa.edu.cn`。

## 步骤 3 和步骤 4

有了 `base_url` 以后，请求 `base_url/`。

这一步恢复自动跟随重定向。目标不是判断是否存在 portal，而是拿到真正的登录落地页。

若最终响应体里仍然存在 JS 跳转或 `meta refresh`，会继续解析跳转地址。若地址是相对路径，会基于当前页面 URL 转成绝对路径。

当前北航环境的典型链路如下。

| 阶段 | URL |
| --- | --- |
| 根路径 | `https://gw.buaa.edu.cn/` |
| 中间页 | `https://gw.buaa.edu.cn/index_1.html` |
| 最终登录页 | `/srun_portal_pc?ac_id=78&theme=buaa` |

真正用于提取参数的是最终登录页 URL。

## 每个参数的探测逻辑

| 参数 | 来源 | 读取方式 | 备注 |
| --- | --- | --- | --- |
| `base_url` | portal 入口 URL | 取 URL 的 `scheme + host` | 例如 `https://gw.buaa.edu.cn` |
| `ac_id` | 最终登录页 URL 查询串 | 先取 `ac_id`，再取 `acid`，最后正则兜底 | 当前登录必需 |
| `nas_ip` | 最终登录页 URL 查询串 | 直接取 `nas_ip` | 可选 |
| `ap_id` | 最终登录页 URL 查询串 | 直接取 `ap_id` | 可选 |
| `ap_ip` | 最终登录页 URL 查询串 | 直接取 `ap_ip` | 可选 |
| `mac` | 最终登录页 URL 查询串 | 直接取 `mac` | 可选 |
| `theme` | 最终登录页 URL 查询串 | 直接取 `theme` | 当前仅记录，不参与登录计算 |

## 合并规则

探测结果可能来自两处，一处是 captive portal 第一跳，另一处是最终登录页。

合并规则只有一条。

后来的值只补空字段，不覆盖已有非空字段。

实现函数是 `mergeDiscoveredParams`。

这意味着第一跳若已经给出 `ac_id`，后续步骤只会补充缺失字段。第一跳若没给，最终登录页给了，就以后者为准。

## 回填规则

探测结束后，`Config.ApplyDiscovery` 会把以下字段写回配置。若这些字段原本是用户手动配置的，启动阶段不会主动刷新它们。只有缺少关键入口参数，或登录登出失败后触发重新探测时，才可能被新值覆盖。

| 字段 | 是否回填 |
| --- | --- |
| `base_url` | 是 |
| `ac_id` | 是 |
| `nas_ip` | 是 |
| `ap_id` | 是 |
| `ap_ip` | 是 |
| `mac` | 是 |
| `theme` | 是 |

## 失败后的重新探测

| 场景 | 是否重新探测 |
| --- | --- |
| 登录失败，且错误不像账号或密码问题 | 是，重新探测一次，再重试一次 |
| 登出失败，且错误不像账号或密码问题 | 是，重新探测一次，再重试一次 |
| 账号不存在、密码错误、账户锁定、强制改密这类错误 | 否 |

这一步的目的，是处理用户移动位置后 `ac_id` 或其他入口参数失效的情况。重新探测不会只修 `ac_id`，而是把当前页面能拿到的 `ac_id`、`nas_ip`、`ap_id`、`ap_ip`、`mac`、`theme` 全部一起刷新。

## 登录时实际使用的字段

`internal/protocol/protocol.go` 的 `Login` 会使用这些探测结果。

| 字段 | 用途 |
| --- | --- |
| `base_url` | 决定请求发往哪台网关 |
| `ac_id` | 参与 `info`、`chksum` 和 `/cgi-bin/srun_portal` 请求 |
| `nas_ip` | 作为登录请求参数透传 |
| `ap_id` | 作为登录请求参数透传 |
| `ap_ip` | 作为登录请求参数透传 |
| `mac` | 作为登录请求参数透传 |
| `theme` | 当前不参与登录请求，仅保留 |

## 最小复现流程

| 顺序 | 动作 | 结果 |
| --- | --- | --- |
| 1 | 请求一个外网探针 URL，关闭自动重定向 | 拿到 portal 入口 |
| 2 | 从 portal 入口提取 `scheme + host` | 得到 `base_url` |
| 3 | 请求 `base_url/`，允许跟随重定向 | 落到真正登录页 |
| 4 | 若响应体里仍有 JS 或 `meta refresh` 跳转，继续解析 | 得到最终登录页 URL |
| 5 | 从最终 URL 查询串读取 `ac_id`、`nas_ip`、`ap_id`、`ap_ip`、`mac`、`theme` | 得到完整参数集 |

按这个流程复现，得到的结果应与当前脚本一致。
