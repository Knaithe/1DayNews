# Web 仪表盘

只读 SQLite 浏览器，暖色卡片式界面，只绑 localhost。

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
| 后端 | Flask，单文件 `src/web.py` |
| 前端 | 内嵌 HTML/CSS/JS，无构建步骤 |
| 数据库 | 只读打开 SQLite（`?mode=ro`） |
| 字体 | Syne（标题）+ DM Sans（正文）+ JetBrains Mono（CVE ID） |
| 缓存 | `Cache-Control: no-store`，F5 永远拿最新数据 |

## 设计风格

暖色系，灵感来自 [pluto.security](https://pluto.security/blog/)：

- 奶油色渐变背景（`#FBF0DF` + 桃色/黄色径向光晕）
- 白色卡片 + 大圆角 22px + hover 浮起阴影
- 卡片左侧彩色严重性条纹（critical=红 / high=橙 / medium=黄 / low=沙色）
- 柔和 badge 配色（浅底深字，如 CISA_KEV = 浅红底 `#FFE0E0` + 深红字 `#b91c1c`）
- 药丸形源分类标签栏（可点击过滤）
- 入场 fadeUp 动画

## API 端点

所有端点返回 JSON，可供外部工具调用（同样只绑 localhost）。

### GET /api/vulns

查询漏洞列表。

| 参数 | 类型 | 说明 |
|---|---|---|
| `q` | string | 搜索 CVE/标题/摘要（子串） |
| `source` | string | 精确匹配源名称 |
| `reason` | string | 精确匹配 reason |
| `pushed` | `1` | 只返回推送过的 |
| `days` | int | 只返回最近 N 天 |
| `limit` | int | 最大条数（默认 100，上限 500） |

返回示例：

```json
[
  {
    "id": "CVE-2026-1340",
    "source": "CISA_KEV",
    "title": "[KEV] CVE-2026-1340 Ivanti EPMM Code Injection",
    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1340",
    "summary": "Pre-auth code injection...",
    "reason": "RCE+asset/CVE",
    "pushed": true,
    "date": "2026-04-26 15:25"
  }
]
```

### GET /api/stats

返回统计概览：`total`、`pushed`、`sources`（按源计数）、`reasons`（按原因计数）。

### GET /api/sources

返回所有已知源名称列表。

## 安全

- **默认只绑 127.0.0.1**：不暴露到公网
- **只读 SQLite**：`file:xxx?mode=ro`，Web 界面无法修改数据
- **无认证**：依赖网络层隔离（localhost + SSH），不依赖应用层认证
- **无缓存**：`Cache-Control: no-store`，不在浏览器/代理缓存敏感数据
- **零额外依赖**：只需 Flask，前端内嵌无 CDN 运行时依赖（字体除外）

如需公网暴露（不推荐），加 Nginx 反代 + Basic Auth + HTTPS。

## 生产部署

可选：加一个 systemd unit 让仪表盘常驻后台。

```ini
# /etc/systemd/system/vuln-web.service
[Unit]
Description=vuln-monitor web dashboard
After=network.target

[Service]
Type=simple
User=vuln
ExecStart=/opt/vuln-monitor/venv/bin/python /opt/vuln-monitor/src/web.py
Restart=on-failure
Environment=VULN_DATA_DIR=/opt/vuln-monitor

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now vuln-web.service
```
