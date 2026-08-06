# WebVulnScanner v8.0

> **全功能 Web 漏洞扫描工具**
> Author: 火柴 | GitHub: [huocai250](https://github.com/huocai250)
> ⚠️ **仅供授权渗透测试与安全研究使用，未经授权扫描属于违法行为！**

WebVulnScanner 是一款**检测 / 评估型**安全扫描器（与 OWASP ZAP、Nikto、Nuclei 同类）：
它探测目标是否存在常见漏洞、梳理攻击面并给出整改建议，**不包含利用、提权、
数据窃取或持久化功能**（详见下方「关于漏洞利用」）。请仅在已获得书面授权的目标上使用。

---

## 检测模块（26 个）

| 模块 | 检测内容 |
|------|---------|
| 爬虫 | 发现同源 URL / 参数 / 表单，构建真实测试面 |
| 信息收集 | Server 头、技术栈、WAF、DNS、robots.txt |
| **指纹识别** 🆕 | 60+ 规则：服务器 / 语言 / 框架 / CMS / CDN / WAF / 前端库 |
| 安全头检测 | HSTS / CSP / X-Frame-Options / Cookie 安全 等 9 项 |
| SSL/TLS | 证书有效期、旧版协议、配置错误 |
| 敏感信息 | AWS Key / 私钥 / 密码 / JWT / .git / .env 等 20+ |
| **配置错误 / 点击劫持** 🆕 | frame 保护、目录列表、调试模式、详细报错 |
| HTTP 方法 | PUT / DELETE / TRACE / WebDAV |
| GraphQL | introspection 是否对外开放 |
| Host 头注入 | Host / X-Forwarded-Host 信任问题 |
| **JWT 安全** 🆕 | alg=none / 缺少 exp / 敏感声明 / 弱算法提示（**不爆破密钥**） |
| **CMS 专项** 🆕 | WordPress / Joomla / ThinkPHP / Spring Actuator / Shiro 暴露面 |
| CORS | 通配符 / 反射 Origin / null Origin / Credentials |
| CSRF | POST 表单 Token 检测 |
| 开放重定向 | 多参数 × 多 Payload（Location + meta refresh） |
| **CRLF 注入** 🆕 | HTTP 响应拆分（带内检测注入响应头） |
| SQL 注入 | 报错 / 布尔盲注 / 时延盲注（含二次确认） |
| XSS | 反射型 XSS / SSTI / DOM 分析 |
| LFI/RCE | 本地文件包含 / 命令注入 |
| **路径穿越** 🆕 | 编码 / 归一化绕过变体（仅确认存在，不外带文件） |
| **XXE 注入** 🆕 | 带内实体展开检测（**不读文件、不外带**） |
| **SSRF** 🆕 | canary 注入检测（**不读云元数据 / 不探内网**） |
| **Log4Shell** 🆕 | CVE-2021-44228 JNDI 探测（需自建 collaborator 确认） |
| **子域名枚举** 🆕 | DNS 字典枚举攻击面（需网络与授权） |
| 端口扫描 | 高危端口（Redis/MongoDB/ES/Docker 等）+ banner |
| 目录枚举 | 敏感路径 + 自定义字典 + 软 404 过滤 |

---

## 新增基础设施 🆕

- **Web UI**：`--web` 启动 Flask 界面，SSE 实时进度、在线查看结果与报告
- **插件系统**：`--plugins DIR` 从目录热加载自定义 `BaseScanner` 子类
- **批量扫描**：`-f targets.txt` 用 asyncio 并发扫描多目标（`--concurrency N`）
- **配置文件**：`--config scanner.cfg` 集中管理默认参数（命令行优先级更高）
- **风险评分 / 修复建议 / 多格式报告**：JSON / HTML / Markdown / CSV
- **负责任扫描护栏**：作用域锁定、限速（令牌桶）、礼貌延迟、被动模式

---

## 安装

```bash
pip install -r requirements.txt
# Web UI 额外需要：
pip install flask
```

## 用法

```bash
# 基本扫描
python main.py https://example.com

# 快速模式 + HTML 报告
python main.py https://example.com --fast --html report.html

# 被动模式（非侵入式，只做安全检测）
python main.py https://example.com --passive

# 使用配置文件 + 插件
python main.py https://example.com --config scanner.cfg --plugins plugins

# 带外探测（Log4Shell/SSRF）指定你自己的 collaborator
python main.py https://example.com --canary your.collaborator.net

# 批量扫描（并发 5 个目标）
python main.py -f targets.txt --concurrency 5 --html out.html

# 启动 Web UI
python main.py --web        # 打开 http://127.0.0.1:5000

# 作为模块运行
python -m webscanner https://example.com
```

常用参数：`-t/--threads`、`--rate`（限速）、`--proxy`、`--cookie`、`--header`、
`--scope`、`--skip MODULE`、`-o/--output`（JSON）、`--md`、`--csv`、`--log`、
`-y/--yes`（跳过授权确认）。完整列表见 `python main.py -h`。

---

## 编写插件

在 `plugins/` 放一个 `.py`，定义继承 `BaseScanner` 的类即可（参考
`plugins/example_plugin.py`）：

```python
from core.scanner import BaseScanner
from core.colors import log

class MyScanner(BaseScanner):
    name = "my_check"       # 唯一名，可用 --skip my_check 跳过
    passive = True          # 非侵入式则设 True

    def run(self):
        r = self.get(self.url("/some/path"))
        if r and "secret" in (r.text or ""):
            self.add("信息泄露", "MEDIUM", "发现敏感路径", url=r.url)
```

---

## 关于漏洞利用（重要）

本工具**刻意只做「检测」不做「利用」**。它会告诉你某处是否存在 SQL 注入 /
SSRF / XXE / 路径穿越等，并给出证据与整改建议，但**不会**：
自动 dump 数据库内容、反弹 Shell、生成 Cookie 窃取 payload、通过 SSRF 读取
云元数据 / 内网 / 文件、通过 XXE 外带数据，或爆破 JWT 密钥 / 登录口令。

原因：这些「利用」步骤会把「发现弱点」变成「实施攻击 / 窃取数据 / 取得控制权」，
超出了评估型扫描器的职责范围。合法授权的漏洞验证若确需利用，请使用相应的
专用工具，并严格限定在授权范围内。

---

## 免责声明

本工具仅供**授权**的安全测试与教育研究。使用者须确保已获得目标系统所有者的
**书面授权**。任何未经授权的扫描或攻击均属违法，开发者不对滥用行为负责。
