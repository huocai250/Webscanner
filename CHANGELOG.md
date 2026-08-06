# 更新日志

## v8.0.0

### ✨ 新增检测模块（10 个）
- **指纹识别** `modules/fingerprint.py`：60+ 规则被动识别服务器 / 语言 /
  框架 / CMS / CDN / WAF / 前端库，结果供 CMS 专项等模块消费。
- **JWT 安全** `modules/jwt_check.py`：静态分析 alg=none、缺少 exp、
  敏感声明、弱对称算法提示（**不破解密钥、不伪造 token**）。
- **配置错误 / 点击劫持** `modules/misconfig.py`：frame 保护缺失、目录列表、
  调试模式与详细报错泄露。
- **CMS 专项** `modules/cms.py`：WordPress 用户枚举 / xmlrpc、Joomla 备份、
  ThinkPHP、Spring Boot Actuator、Apache Shiro 暴露面检测（**仅检测不利用**）。
- **CRLF 注入** `modules/crlf.py`：带内检测响应头注入（响应拆分）。
- **路径穿越** `modules/traversal.py`：编码 / 归一化绕过变体，仅确认漏洞存在。
- **XXE 注入** `modules/xxe.py`：带内实体展开检测（**不读文件、不外带**）。
- **SSRF** `modules/ssrf.py`：canary 注入检测（**不读云元数据 / 不探内网 / 不读文件**）。
- **Log4Shell** `modules/log4shell.py`：CVE-2021-44228 JNDI 探测标记注入
  （需自建 collaborator 观测回连确认；**不部署 JNDI 服务、不投递 payload**）。
- **子域名枚举** `modules/subdomain.py`：DNS 字典枚举攻击面（需网络与授权）。

### 🏗️ 新增基础设施
- **统一扫描引擎** `core/engine.py`：抽出单目标扫描主循环，供 CLI / 批量 /
  Web UI 共用，支持进度回调。
- **Web UI** `webui/app.py`：Flask + SSE 实时进度界面，`--web` 启动，
  在线查看结果与保存 HTML 报告（含授权确认）。
- **插件系统** `core/plugins.py` + `plugins/`：`--plugins DIR` 热加载自定义
  `BaseScanner` 子类；附示例插件。
- **批量 / 异步多目标** `core/batch.py`：`-f targets.txt` 用 asyncio 并发扫描
  多目标（`--concurrency N`），基于标准库、不依赖 aiohttp。
- **配置文件** `core/configfile.py` + `scanner.cfg.example`：`--config` 读取 INI，
  命令行参数优先级更高。
- 新增 `--canary` 参数统一带外探测域名；`--fast` 现同时跳过子域名 / Log4Shell。

### 🐛 Bug 修复
- **指纹版本误套**：CMS 的 meta generator 版本会被错误套用到 PHP / 语言 /
  服务器（如把 WordPress 5.8 显示成 "PHP 5.8"）。改为按来源精确取版本
  （PHP 取自 X-Powered-By、服务器取自 Server 头、generator 仅用于 CMS）。

### ⛔ 刻意未实现（安全边界）
以下「利用」类功能**不予实现**，因其会把「发现弱点」变为「实施攻击 / 窃取
数据 / 取得控制」：SQLi 自动 dump 数据库、命令注入反弹 Shell、XSS Cookie
窃取 payload、LFI 自动读取敏感文件 / 源码、SSRF 读云元数据 / 内网探测 / 文件
读取、XXE 数据外带、JWT 密钥爆破、弱口令爆破。对应能力均以**检测版**提供。

---

## v4.0.0

### 🐛 Bug 修复
- **SSL 旧版协议探测逻辑错误**：v3 中三个分支被固定成同一版本（TLS1.0），
  无法真正区分 SSLv3 / TLS1.0 / TLS1.1。v4 逐版本尝试握手，准确识别。
- **`datetime.utcnow()` 弃用**：改用 timezone-aware 的 `datetime.now(timezone.utc)`，
  修复证书有效期计算在 Python 3.12+ 的告警与潜在偏差。
- **HTML 报告可被注入（存储型 XSS）**：v3 将 finding 的 detail/evidence/url 直接拼进
  HTML。若目标反射了脚本并进入证据字段，打开报告即可能执行。v4 对所有动态字段
  统一 `html.escape`。
- **注入模块从不并发**：v3 为 SQLi/XSS/LFI/重定向传入了 `threads` 但从未使用，
  全部串行，极慢。v4 通过共享线程池并发测试。
- **只测猜测的参数名**：v3 忽略了目标 URL 里已有的参数（最重要的测试面）。
  v4 由爬虫发现真实参数与表单再测试。

### ✨ 新功能
- **爬虫模块**（`modules/crawler.py`）：BFS 爬取同源页面，发现带参 URL 与表单，
  作为注入点供各主动模块测试（支持 `--max-urls` / `--max-depth` / `--no-crawl`）。
- **HTTP 方法检测**（`modules/methods.py`）：探测 PUT/DELETE/TRACE/CONNECT 与 WebDAV。
- **GraphQL introspection 检测**（`modules/graphql.py`）：识别对外开放的 introspection。
- **Host 头注入检测**（`modules/hostheader.py`）：Host / X-Forwarded-Host 信任问题。
- **被动模式** `--passive`：只运行非侵入式检测，不注入 payload、不做端口扫描。
- **作用域护栏** `--scope`：限制可扫描主机；默认锁定目标主机，越界请求自动跳过。
- **授权确认**：交互式运行时要求确认已获授权（`-y/--yes` 可跳过用于自动化）。
- **负责任扫描**：`--delay` / `--jitter` / `--rate` 控制请求速率，降低目标负载。
- **失败重试**：`--retries` 指数退避重试瞬时网络错误。
- **风险评分**：0–100 综合评分与等级，展示于终端与各报告。
- **修复建议**：每类问题附带整改建议，写入 HTML / Markdown / JSON / CSV。
- **多格式报告**：新增 Markdown (`--md`) 与 CSV (`--csv`) 导出。
- **文件日志** `--log`、静默模式 `-q`、`--no-color`、`--random-agent`、`--verify-ssl`。
- **软 404 校准**：目录枚举先测不存在路径的响应，过滤 wildcard 200 误报。
- **端口 banner 抓取**：提升服务识别准确性。
- **单元测试**：`tests/test_units.py` 覆盖解析、作用域、去重、评分等纯函数。

### 🏗 重构与优化
- 统一 `ScanConfig` 配置对象 + `ScanContext` 运行时上下文，替代到处传 `**kwargs`。
- 基线响应缓存，避免重复抓取首页。
- 结果自动去重；`requests.Session` 连接池调优。
- 默认不再自动落地 HTML 报告（改为 `--auto-report` 显式开启）。
- 支持 `python -m webscanner`。

### ⚠️ 说明
本工具是**检测/评估**工具：它探测漏洞是否存在并给出整改建议，不包含任何
利用、提权、数据窃取或持久化功能。仅供已获书面授权的渗透测试与安全研究使用。
