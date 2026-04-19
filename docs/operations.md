# 运维

## 凭证存储位置

按场景分两处，程序启动时按"环境变量 > 本地配置 > 空"的优先级解析：

| 场景 | 位置 | 写入方式 | 权限 |
|---|---|---|---|
| 服务器 / systemd | `/opt/vuln-monitor/.env` | `deploy.sh` 写（交互或 env 传参） | `chmod 600`，owner `vuln` |
| 本地开发 / 个人机 | `~/.config/vuln-monitor/config.json`（Linux/macOS）<br>`%APPDATA%\vuln-monitor\config.json`（Windows） | `python scripts/configure.py` | POSIX 下 `chmod 600`，Windows 靠 `APPDATA` 天然隔离 |
| CI / 一次性 | 环境变量 | `TG_BOT_TOKEN=... python src/vuln_monitor.py` | — |

完整的解析优先级和文件格式见 [`architecture.md`](architecture.md#凭证解析规则telegram--github-token)。

## 进程保护：文件锁

位置：`DATA_DIR/vuln_monitor.lock`
实现：`SingletonLock` 类，POSIX 用 `fcntl.flock(LOCK_EX | LOCK_NB)`，Windows 用 `msvcrt.locking(LK_NBLCK)`

- **非阻塞**：另一实例在跑时立刻退出（exit code 0，无告警）
- **进程异常退出**：OS 自动释放 flock / Windows locking
- **手动留着的锁文件**：重启机器后内核 flock 不再生效，文件内容不重要

systemd timer 如果前一次还没跑完，下一次触发自然被锁挡住——不用配 `OnUnitActiveSec` 额外串行化。

## 原子写

位置：`save_cache()` 与 `send_failure_alert()` 的状态保存

```python
tmp = target.with_suffix(target.suffix + ".tmp")
tmp.write_text(json.dumps(data), encoding="utf-8")
os.replace(tmp, target)      # POSIX 原子，Windows 10+ 近似原子
```

- 即使写 cache 的过程被 kill -9，磁盘上要么是旧 cache 要么是完整新 cache，不会出现半截 JSON
- 避免下一次启动时 `json.loads()` 炸 → 整个程序无法启动

## 日志轮转

位置：`DATA_DIR/vuln_monitor.log` + `.1 ~ .5` 五个归档

```python
RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
```

- 单文件 5MB 触发轮转
- 最多保留 5 份归档 → 磁盘占用上限 25MB
- 首次 KEV 预热那次日志最大（会写 1500+ 条 DRY 记录）
- 之后每次触发只几 KB

同时走 `StreamHandler(sys.stdout)` 一份 → systemd 自动收进 `journalctl -u vuln-monitor.service`。

## 失败告警限流

位置：`DATA_DIR/vuln_alert_state.json`

- 当抓源或推送 Telegram 连续失败时，`send_failure_alert()` 会尝试告警（发 TG 消息或记到日志）
- **限流规则**：同一种错误每 3600 秒最多发一次
- 状态文件结构：`{"last_alert_ts": <unix-timestamp>}`
- 为什么要限流：源站挂一小时 → 无限流会每 5 分钟告警一次 → 12 条告警淹没主消息流

冷却时间在 `ALERT_COOLDOWN_SEC = 3600` 常量里调。

## systemd 沙盒

service 单元里的硬化指令（按防御强度排序）：

| 指令 | 作用 | 代价 |
|---|---|---|
| `User=vuln` / `Group=vuln` | 非 root 运行 | 无 |
| `NoNewPrivileges=true` | 禁 setuid 提权路径 | 无 |
| `ProtectSystem=strict` | `/` 全只读（除 `ReadWritePaths`） | 需显式列可写路径 |
| `ProtectHome=true` | `/home`、`/root` 不可见 | 无 |
| `PrivateTmp=true` | 独立 `/tmp` | 无 |
| `PrivateDevices=true` | 仅 `/dev/null`、`/dev/random` 等 | 无 |
| `ProtectKernelTunables=true` | `/proc/sys`、`/sys` 只读 | 无 |
| `ProtectKernelModules=true` | 禁加载内核模块 | 无 |
| `ProtectControlGroups=true` | cgroup 只读 | 无 |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | 限制 socket 类型 | 无（不用 netlink） |
| `RestrictNamespaces=true` | 禁用 namespace 创建 | 无 |
| `LockPersonality=true` | 禁 `personality()` 系统调用 | 无 |
| `MemoryDenyWriteExecute=true` | 禁 W^X 映射 | 无（Python 不依赖 JIT） |
| `RestrictRealtime=true` | 禁实时调度 | 无 |
| `SystemCallFilter=@system-service` | seccomp 白名单 | 偶有漏补丁需要排查 |
| `SystemCallErrorNumber=EPERM` | 被拦截的 syscall 返回 EPERM 而非 kill | 便于调试 |

如果 Python 升级后突然起不来，先怀疑 `SystemCallFilter`：`journalctl -u vuln-monitor.service` 会打 `Operation not permitted`，然后 `systemd-analyze syscall-filter @system-service` 看是哪一类被挡。

## 资源限制

```
RuntimeMaxSec=600       # 单次跑最多 10 分钟（首次预热除外）
Nice=10                 # 低 CPU 优先级
IOSchedulingClass=best-effort
IOSchedulingPriority=7  # 最低 I/O 优先级
```

前台有别的东西跑时，本脚本自动退让——不会和主业务抢 CPU/IO。

## Timer 策略

```
OnBootSec=2min          # 开机 2 分钟后首触发
OnUnitActiveSec=5min    # 此后每 5 分钟（从上一次"完成"算起）
AccuracySec=30s         # 触发时间误差 ±30s
Persistent=true         # 机器关过机也会补跑一次
```

`OnUnitActiveSec`（不是 `OnCalendar`）的含义：两次执行之间间隔 5 分钟——如果某次跑了 8 分钟，下一次是 8+5=13 分钟后开始，不会堆积触发。

## 运行时观察命令

```bash
# 下次触发时间
systemctl list-timers vuln-monitor.timer

# 实时 journal（推荐）
journalctl -u vuln-monitor.service -f

# 文件日志（更长保留）
tail -f /opt/vuln-monitor/vuln_monitor.log

# 手动触发一次（不影响下一次定时触发）
sudo systemctl start vuln-monitor.service

# 看上一次运行状态与退出码
systemctl status vuln-monitor.service

# 完全停掉（禁止再触发）
sudo systemctl disable --now vuln-monitor.timer

# 看 cache 有多少条（诊断）
jq '.seen | keys | length' /opt/vuln-monitor/vuln_cache.json
```

## 常见故障定位

| 症状 | 原因 | 排查 |
|---|---|---|
| 服务器 timer 跑了但没推送 | dry mode（`.env` 没加载或字段为空） | `systemctl cat vuln-monitor.service` 看 `EnvironmentFile` 路径；`cat /opt/vuln-monitor/.env` 确认 `TG_BOT_TOKEN/TG_CHAT_ID` 有值 |
| 本地跑了但没推送 | 配置文件缺失或字段为空 | `python scripts/configure.py --show` 看当前配置；`--path` 查文件位置 |
| 每次都推一堆历史 CVE | cache 丢了或权限错 | `ls -la /opt/vuln-monitor/vuln_cache.json`，应当 `vuln:vuln` 可写 |
| 抓源一直 timeout | 出口到源站网络问题 | 部署地不在海外时，`HTTPS_PROXY` 走代理；或换美国 VPS |
| 某源 404 | 源 URL 变了 | `python scripts/probe_feeds.py` 找新 URL |
| Telegram 推送失败 | token 错 / chat\_id 错 / bot 未加入频道 | 手动 `curl "https://api.telegram.org/bot$TOKEN/getMe"` 验 token；bot 要被**拉进频道并设为 admin** 才能发 |
| journal 里报 "Operation not permitted" | 沙盒指令误伤 | 临时注释 `SystemCallFilter=@system-service`，重跑看具体失败行，再定位 |
