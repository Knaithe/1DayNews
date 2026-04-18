# 架构设计

## 目录布局

```
1DayNews/
├── src/
│   └── vuln_monitor.py        # 主程序（所有逻辑都在这一个文件里）
├── scripts/
│   └── probe_feeds.py         # 源失效时用来批量探测替代 URL 的工具
├── systemd/
│   ├── vuln-monitor.service   # oneshot 服务单元（带完整沙盒指令）
│   └── vuln-monitor.timer     # 5 分钟触发定时器
├── docs/
│   ├── architecture.md        # 本文
│   ├── sources.md             # 信息源清单与取舍理由
│   ├── filtering.md           # 过滤逻辑（RCE/资产/黑名单/score）
│   └── operations.md          # 运维：锁、原子写、日志、告警限流
├── deploy.sh                  # 一键部署脚本
├── requirements.txt
├── env.example                # .env 模板
└── README.md                  # 速览与快速开始
```

## 部署布局（服务器）

```
/opt/vuln-monitor/
├── src/vuln_monitor.py        # code（跟仓库结构一致）
├── scripts/probe_feeds.py
├── systemd/*.{service,timer}
├── venv/                      # Python 虚拟环境（deploy.sh 创建）
├── .env                       # 敏感变量，600
├── vuln_cache.json            # ←│
├── vuln_monitor.lock          # ←│ runtime state（DATA_DIR，跟代码分离）
├── vuln_monitor.log[.1-.5]    # ←│
└── vuln_alert_state.json      # ←│
```

**代码（`src/`）与运行态（根目录）分离**的目的：

- 升级（`git pull`）只动 `src/`，不会误删/误写 cache 或日志
- `ProtectSystem=strict` 只需要把 `/opt/vuln-monitor` 整体设为 `ReadWritePaths`
- 本地 `python src/vuln_monitor.py` 开发时，state 文件自动落在仓库根（见下方 `DATA_DIR` 规则）

## DATA_DIR 解析规则

Python 启动时按优先级决定运行态文件放哪：

```python
1. $VULN_DATA_DIR (env)            ← systemd 在 service 里 pin 成 /opt/vuln-monitor
2. SCRIPT_DIR.parent if name=="src" ← 仓库里跑 `python src/vuln_monitor.py`，落在仓库根
3. SCRIPT_DIR                       ← 单文件直接跑，就地落
```

好处是三种场景都不需要手动配置：systemd 运行、仓库里开发、临时下载脚本调试。

## 数据流水线

```
┌────────────────────────────────────────────────────────────────────┐
│                          main() 入口                                │
└──────────────────┬─────────────────────────────────────────────────┘
                   │
                   ▼
      ┌───────────────────────────┐
      │  SingletonLock (fcntl /    │  非阻塞：已有实例在跑就直接退出
      │  msvcrt)                   │
      └──────────────────┬────────┘
                         │
                         ▼
            ┌─────────────────────────┐
            │  load cache (60d TTL)   │  key=CVE 号，无 CVE fallback 到 SHA1(title+link)
            └────────────┬────────────┘
                         │
    ┌────────────────────┼────────────────────────────┐
    │                    │                            │
    ▼                    ▼                            ▼
 fetch_rss()*12     fetch_kev_json()           fetch_github_cve()
 (vendor + research + sploitus)   (1500+ 结构化条目)    (CVE-YYYY- 仓库，最近创建)
    │                    │                            │
    └────────────────────┼────────────────────────────┘
                         │
                         ▼
                  ┌─────────────┐
                  │  去重（CVE  │  cache hit → 跳过
                  │   为主键）  │
                  └──────┬──────┘
                         │
                         ▼
                  ┌─────────────┐
                  │   score()   │  RCE_PATTERNS ∧ ¬EXCLUDE_PATTERNS ∧ (ASSET_KEYWORDS ∨ CVE号)
                  └──────┬──────┘
                         │
                ┌────────┴────────┐
                │                 │
            score>0          score==0
                │                 │
                ▼                 ▼
        send_telegram()       filter / log only
                │
                ▼
        写回 cache（原子：tmp + os.replace）
                │
                ▼
        释放锁，退出
```

## 为什么是 pull-batch 而不是 daemon

- 源本身不是实时（RSS 刷新周期通常 > 5 分钟，KEV 每天更新一次）
- pull-batch 的失败代价 = 少一次触发，下一轮继续；daemon 崩了就彻底停
- systemd timer + oneshot 天然支持"跑完就退出 + 下次重新拉起"，不用自己写守护循环
- 5 分钟粒度对 0day/1day 足够——实际瓶颈是源刷新频率，不是我们的轮询频率

## 去重为什么用 CVE 号

- 同一 CVE 会出现在多个源（ZDI 先披露 → KEV 几天后纳入 → GitHub 几天后 PoC → watchTowr 写文章）
- 如果按 URL 去重会重复推 4~5 次；按 CVE 号去重只推第一次
- 例外：极少数源（早期 GreyNoise trend 博客）没 CVE 号，此时 fallback 到 `SHA1(title+link)` 保证不丢

## 首次"预热"机制

首次真推 Telegram 会看到一堆过去几十天的历史 CVE——**不能直接让 systemd 开跑**。

`deploy.sh` 的做法：

```bash
sudo -u vuln env -i \
    VULN_DATA_DIR=/opt/vuln-monitor \
    PATH=/usr/bin:/bin \
    /opt/vuln-monitor/venv/bin/python /opt/vuln-monitor/src/vuln_monitor.py
```

- `env -i` 清空所有 env → `TG_BOT_TOKEN` 不存在 → 脚本进入 dry mode → 只写 cache 不推送
- 这一跑会把 1900+ 条当前"存量"全部标记成"已见"
- 然后 `systemctl enable --now vuln-monitor.timer` 接管 → 之后只推增量

这一步失败也没关系（`|| true`）——timer 第一次触发时 cache 没热，会推一次历史刷屏，但不是永久问题。

## 下一步可能的演进

暂未实现但设计已预留：

| 功能 | 位置 | 思路 |
|---|---|---|
| 按严重性分频道 | `score()` + `send_telegram()` | score 返回 dict 带等级，不同等级路由到不同 chat_id |
| Webhook 替代 Telegram | `send_telegram()` 同级加 `send_webhook()` | 抽象出 `Notifier` 基类 |
| 多实例聚合 | `cache_key` 加实例前缀 | 适用于多个研究员共用 |
| LLM 二次过滤 | `score()` 之后 | 对 score>0 的条目用 LLM 判一次，进一步降噪 |
