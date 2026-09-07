# 更新日志

## v11.0.0

### ✨ 新增检测模块（10 个）
- **HTTP 参数污染 (HPP)** `modules/hpp.py`：重复参数解析行为检测。
- **动词篡改 / 方法覆盖 / WebDAV** `modules/verbtamper.py`：X-HTTP-Method-Override 是否被解析、
  PROPFIND/PUT 等写方法是否开启（只读探测，不改资源）。
- **PHP 包装器 / LFI 向量** `modules/phpwrappers.py`：php://filter、data:// 是否被解析
  （用编码/无害标记判定，不读敏感文件、不执行代码）。
- **DOM XSS 静态分析** `modules/dom_xss.py`：在 JS 中查找「可控源 + 危险汇聚点」组合
  （location.hash → innerHTML/eval 等），只静态分析不执行。
- **CORS 高级绕过** `modules/cors_advanced.py`：null 源、子域信任、前/后缀匹配缺陷、
  明文源被信任等白名单绕过模式。
- **会话固定** `modules/session.py`：是否接受攻击者预置会话 ID 且不重新签发。
- **敏感页缓存** `modules/session.py`：敏感/个性化页面是否缺少 no-store/private 而可能被缓存。
- **WebSocket / 实时端点检测** `modules/websocket.py`：ws/wss、Socket.IO、SignalR 端点发现。
- **全站 PII/密钥深扫** `modules/pii.py`：把密钥/PII 正则应用到所有爬取页面（证据脱敏）。
- **安全头策略深度** `modules/header_policy.py`：Referrer-Policy、Permissions-Policy、
  COOP/COEP/CORP、限流头存在性。
- 另：GraphQL 深度模块新增「别名放大 DoS 面」检测。

### 📈 规则扩充（1500+）
- 敏感路径 671 → **747**（新增云/CI-CD/密钥管理/更多面板与接口路径）。
- 新增 YAML 模板包 `templates/products.yaml`（Consul/K8s/Docker Registry/Spring Gateway 等）。
- 内置检测规则/签名总量 **1520**，启动时如实显示，可继续用模板扩展。

### ⚙️ 优化与 Bug 修复
- **软 404 检测升级**：由「精确长度比对」改为 `difflib` **内容相似度**识别，两个随机探针
  校准、跨模块共享；既减少误报又补上漏报。exposure/dirbust 均改用共享实现。
- **`--max-requests` 请求预算**：新增 CLI 选项与请求层强制上限，超额自动跳过，控制扫描开销。
- **会话固定 Bug 修复**：扫描中途共享 Session 已持有会话 Cookie 导致取不到 Cookie 名；
  改为回退到 Cookie 罐读取，并修正「重签发」判定（回显原值也算未重签发）。
- 沿用 v9/v10 的 SSRF、SSI、反序列化等误报修复；模块异常隔离。
- 经实测：10 个新模块在无漏洞靶机上 **零误报**，在含对应漏洞的端点上均能正确检出
  （CORS 绕过 / PHP 包装器 / 方法覆盖 / WebDAV / HPP / DOM XSS / 会话固定 / WebSocket 已逐一验证）。

### ⛔ 刻意未实现（安全边界，一以贯之）
利用类功能不予实现。新模块（PHP 包装器、CORS 绕过、会话固定等）均只做**检测与加固提示**，
不读取敏感文件、不窃取跨源数据、不劫持会话、不构造任何利用链。

---

## v10.0.0

### ✨ 新增检测模块（17 个）—— 注入类漏洞覆盖趋于完整
- **NoSQL 注入** `modules/nosqli.py`：MongoDB 运算符/布尔差异 + 错误特征。
- **LDAP 注入** `modules/ldap_xpath.py`：LDAP 元字符 + 错误特征。
- **XPath 注入** `modules/ldap_xpath.py`：XPath 元字符 + 错误特征。
- **SSI 注入** `modules/ssi.py`：无害 printenv 探针（要求多个环境变量特征，低误报）。
- **EL/OGNL/SpEL 表达式注入** `modules/prototype.py`：算术求值 + 引擎错误特征。
- **原型链污染** `modules/prototype.py`：`__proto__`/constructor 探针。
- **邮件头注入** `modules/headerinj.py`：邮件参数换行注入。
- **CSV 公式注入** `modules/headerinj.py`：导出字段公式注入（仅在导出响应上判定）。
- **反序列化指示** `modules/deserial.py`：识别 Java/PHP/Python/.NET/Ruby 序列化特征（仅提示，不利用）。
- **源码泄露** `modules/sourcecode.py`：源码文件被当静态文件下载 + 首页 PHP 源码外泄。
- **调试端点** `modules/sourcecode.py`：pprof/expvar/debugbar/rails-info 等诊断端点暴露。
- **CSP 深度评估** `modules/csp.py`：缺失指令、可绕过白名单域、unsafe-inline 无 nonce 等。
- **Cookie 深度分析** `modules/csp.py`：__Host-/__Secure- 前缀、SameSite=None 无 Secure、过宽 Domain。
- **GraphQL 深度** `modules/graphql_deep.py`：字段建议泄露、GET 查询 CSRF、批处理放大。
- **JWT 高级分析** `modules/graphql_deep.py`：kid 注入面、jku/x5u 远程密钥、算法混淆（仅分析，不破解）。
- **OAuth/OIDC 配置** `modules/cachedeception.py`：宽松 redirect_uri、state/PKCE 提示。
- **Web 缓存欺骗** `modules/cachedeception.py`：伪静态后缀导致敏感页被缓存。

### 📈 规则扩充（1300+）
- 指纹规则 56 → **98**（新增大量 CMS/框架/服务器/WAF/CDN 签名）。
- 新增 YAML 模板包 `templates/tokens.yaml`、`templates/misconfig.yaml`。
- 内置检测规则/签名总量 **1391**，启动时如实显示，可继续用模板扩展。

### ⚙️ 优化与 Bug 修复（多轮）
- **共享探测缓存**：新增 `ScanContext.probe_cache` 与 `probe_get()`，exposure/apidocs/
  模板引擎的幂等路径探测共享缓存，去除跨模块重复请求，降低请求量与目标压力。
- **SSI 误报修复**：原签名含 `:`/`20` 等极易命中的字符会误报；改为只认多个服务器
  环境变量特征（需 ≥2 命中）。
- **反序列化 PHP 特征收紧**：只认结构化对象/数组前缀（`O:`/`a:`），不再把 JSON 误判。
- **调试端点判定逻辑修复**：无签名项在 200/405 下的判定统一，去除逻辑漏判。
- 沿用 v9 的 SSRF 误报修复；模块异常隔离，单模块出错不影响整体扫描。
- 经实测：新注入模块在无漏洞的靶机上 **零误报**，在有漏洞端点上均能正确检出。

### ⛔ 刻意未实现（安全边界，一以贯之）
利用类功能不予实现：自动 dump/反弹 Shell/Cookie 窃取/SSRF 读云元数据·内网·文件/
XXE 外带/口令·密钥爆破。反序列化、JWT、OAuth 等均只做**检测与加固提示**，不构造
任何利用链。

---

## v9.0.0

### ✨ 模板签名引擎（核心新增）
- **YAML 模板引擎** `core/template_engine.py` + `modules/nuclei.py`：nuclei 风格的
  声明式签名库，支持 status/word/regex/header 匹配器与 and/or 组合、多路径、
  负向匹配。内置 `templates/`（exposures/panels/cves 等）并支持 `--templates DIR`
  追加。**新增检测无需改代码**，只需新增 YAML 文件。引擎不执行模板中的任何代码。

### ✨ 新增检测模块（10+）
- **敏感路径暴露** `modules/exposure.py` + `core/data/exposures.py`：600+ 条公开已知
  敏感/配置/备份/面板路径（含备份文件模糊测试），软 404 基线 + 内容签名降噪。
- **JS 密钥/端点** `modules/jssecrets.py`：抓取外链 JS，检索硬编码密钥并提取隐藏接口。
- **API 文档发现** `modules/apidocs.py`：Swagger/OpenAPI/GraphQL/WSDL 等端点暴露检测。
- **前端安全** `modules/frontend.py`：SRI 缺失、混合内容、CSP 质量（unsafe-inline 等）。
- **缓存投毒指示** `modules/cachepoison.py`：非缓存键头反射检测（非破坏）。
- **版本漏洞提示** `modules/cve_version.py`：基于指纹版本比对已知高危版本并提示。
- **robots/well-known 情报** `modules/wellknown.py`：Disallow 敏感路径线索、sitemap、
  crossdomain 通配符、security.txt。
- **子域名接管指纹** `modules/takeover.py`：识别指向未认领第三方服务的接管风险。

### ⚙️ 优化与 Bug 修复
- **SSRF 误报修复**：v8 会把「参数回显了注入的 URL」这种单纯反射误判为 SSRF，
  且对 id/q 等非 URL 参数也触发。v9 只测试「URL 汇聚参数」（参数名属 URL 类或
  原值像 URL），并要求「服务端确实尝试请求」的连接错误特征，反射仅对 sink 参数
  标信息级。经实测 id/q 不再误报。
- **端口库扩充**：高危端口从约 35 增至 68（新增 SNMP/LDAP/rsync/RMI/NFS/etcd/
  AJP/Consul/Webmin/RabbitMQ/CouchDB 等）。
- **启动展示规则总量**：`total_checks()` 如实统计并显示内置规则/签名总数（1000+），
  避免夸大。
- 新增 `--templates` 参数与 `templates_dir` 配置项。

### ⛔ 刻意未实现（安全边界，与 v8 一致）
利用类功能不予实现：SQLi 自动 dump、命令注入反弹 Shell、XSS Cookie 窃取、
LFI 读取敏感文件/源码、SSRF 读云元数据/内网/文件、XXE 数据外带、JWT/口令爆破。
对应能力均以**检测版**提供。

---

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
