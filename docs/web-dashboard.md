# Web 仪表盘

只读 SQLite 浏览器，Pluto Security 风格暖色界面，只绑 localhost。

## 启动

```bash
python src/web.py                     # http://127.0.0.1:8001
python src/web.py --port 9000         # 自定义端口
python src/web.py --host 0.0.0.0      # 绑定所有接口（不推荐，除非在内网）
```

远程访问通过 SSH 隧道：

```bash
ssh -L 8001:127.0.0.1:8001 user@server
# 浏览器打开 http://localhost:8001
```

## 技术架构

| 层 | 技术 |
|---|---|
| 后端 | Flask + waitress（多线程生产服务器），单文件 `src/web.py` |
| 前端 | 内嵌 HTML/CSS/JS，无构建步骤 |
| 数据库 | 只读打开 SQLite（`?mode=ro`） |
| 字体 | Poppins（正文）+ Unbounded（标题/数字）+ JetBrains Mono（CVE ID） |
| 缓存 | `Cache-Control: no-store`，F5 永远拿最新数据 |

## 设计风格

暖色系，参考 [pluto.security/blog](https://pluto.security/blog/)：

- 奶油色渐变背景（`#FDF2D4` + 桃色/橙色径向光晕）
- 白色卡片 + 1px 黑边 + hover 4px 黑硬阴影 + 弹性动画
- 严重性药丸标签（Critical=红 / High=橙 / Medium=黄 / Low=灰）
- CVE ID 用沙色背景等宽字体药丸
- 药丸式筛选器：Source / Reason / Time 各占一行
- Navbar：cream 底色，slim 60px，logo + 搜索 + pushed 开关
- 默认只显示精选（pushed），可切换全量（All）
- 底部 Load more 按钮（每次 +100，上限 500）
- 入场 fadeUp 动画

## 安全

### 响应头

| 头 | 值 | 作用 |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` | 防 XSS/点击劫持/数据外泄 |
| `X-Content-Type-Options` | `nosniff` | 防 MIME 嗅探 |
| `X-Frame-Options` | `DENY` | 防 iframe 嵌入 |
| `Referrer-Policy` | `no-referrer` | 不泄露来源 |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | 禁用不必要的浏览器 API |
| `Cache-Control` | `no-store, no-cache, must-revalidate, max-age=0` | 不缓存敏感数据 |

### 输入防御

- `_int_arg()` 助手：参数类型校验 + 边界 clamp，防止溢出和类型错误
- `esc()` 转义 `& < > " '` 五字符
- `safeUrl()` URL 协议白名单（仅 http/https），阻断 `javascript:` / `data:` 注入
- 所有 `href` 走 `safeUrl()`，`rel` 加 `noreferrer`
- LIMIT 参数化（`?` 占位符），不拼 SQL

### 网络层

- **默认只绑 127.0.0.1**：不暴露到公网
- **只读 SQLite**：`file:xxx?mode=ro`，Web 界面无法修改数据
- **无认证**：依赖网络层隔离（localhost + SSH），不依赖应用层认证

如需公网暴露（不推荐），加 Nginx 反代 + Basic Auth + HTTPS。

## API 端点

所有端点返回 JSON，可供外部工具调用（同样只绑 localhost）。

### GET /api/vulns

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `q` | string | | 搜索 CVE/标题/摘要（子串） |
| `source` | string | | 精确匹配源名称 |
| `reason` | string | | 精确匹配 reason |
| `pushed` | `1` | | 只返回推送过的 |
| `days` | int | 0 | 只返回最近 N 天（上限 3650） |
| `limit` | int | 100 | 最大条数（1-500） |

### GET /api/stats

返回 `total`、`pushed`、`sources`（按源计数）、`reasons`（按原因计数）。

### GET /api/sources

返回所有已知源名称列表。

## 生产部署

`deploy.sh` 已自动安装并启用 `vuln-web.service`。手动管理：

```ini
# /etc/systemd/system/vuln-web.service
[Unit]
Description=vuln-monitor web dashboard
After=network.target vuln-monitor.service

[Service]
Type=simple
User=vuln
ExecStart=/opt/vuln-monitor/venv/bin/python /opt/vuln-monitor/src/web.py
Restart=on-failure
RestartSec=5
Environment=VULN_DATA_DIR=/opt/vuln-monitor
ReadOnlyPaths=/opt/vuln-monitor

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl status vuln-web.service   # 查看状态
sudo systemctl restart vuln-web.service  # 重启
journalctl -u vuln-web.service -f        # 查看日志
```
