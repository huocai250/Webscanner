# WebVulnScanner v4.0

> **全功能 Web 漏洞扫描工具（23个模块）**  
> Author: 火柴 | GitHub: [huocai250](https://github.com/huocai250)  
> ⚠️ **仅供授权渗透测试与安全研究使用，未经授权扫描属于违法行为！**

---

## 功能模块（23个）

| # | 模块 | 检测内容 |
|---|------|---------|
| 1  | 信息收集 | Server头、技术栈、WAF识别、DNS、robots.txt |
| 2  | HTTP 安全头 | HSTS/CSP/X-Frame-Options/Cookie安全 等9项 |
| 3  | SSL/TLS | 证书有效期、旧版协议(TLS1.0/1.1)、配置错误 |
| 4  | 敏感信息泄露 | AWS Key/私钥/密码/JWT/.git/.env 等20+种 |
| 5  | CORS | 通配符/反射Origin/null Origin/Credentials |
| 6  | CSRF | POST表单 Token 检测 |
| 7  | Clickjacking & 配置错误 | iframe保护/目录列表/调试模式/错误信息 |
| 8  | 危险 HTTP 方法 | TRACE/PUT/DELETE/OPTIONS |
| 9  | 开放重定向 | 20+参数 × 多种绕过Payload |
| 10 | JWT 安全 | None算法/弱密钥爆破/敏感字段/无过期时间 |
| 11 | Log4Shell/CRLF/Host Header | CVE-2021-44228/HTTP响应拆分/Host注入 |
| 12 | API 安全 | 未授权访问/GraphQL Introspection/IDOR |
| 13 | SQL 注入 | 报错注入/布尔盲注/时延盲注 |
| 14 | XSS & SSTI | 反射型/存储型/DOM分析/模板注入 |
| 15 | LFI & 命令注入 | 本地文件包含/RCE |
| 16 | 路径穿越 | 40+种绕过Payload(Linux/Windows) |
| 17 | XXE 注入 | XML外部实体注入 |
| 18 | SSRF | 内网探测/云元数据/协议滥用 |
| 19 | 文件上传漏洞 | 扩展名绕过/大小写绕过/双扩展名 |
| 20 | 弱口令检测 | 常见管理后台默认凭据 |
| 21 | 子域名枚举 | 80+常用子域名字典 |
| 22 | 端口扫描 | 30+高危端口(Redis/MongoDB/ES/Docker) |
| 23 | 目录枚举 | 80+敏感路径+支持自定义字典 |

---

## 安装

```bash
pip install -r requirements.txt
```

---

## 使用方法

```bash
# 基础扫描
python main.py https://example.com

# 快速模式（跳过耗时模块）
python main.py https://example.com --fast

# 带认证 + 代理 + 报告
python main.py https://example.com \
  --cookie "session=abc123" \
  --proxy http://127.0.0.1:8080 \
  --output report.json \
  --html report.html

# 只运行指定模块
python main.py https://example.com --only sqli,xss,api

# 跳过特定模块
python main.py https://example.com --skip-ports --skip-dirbust --skip-bruteforce

# 自定义字典
python main.py https://example.com --wordlist /path/to/dirs.txt
```

---

## 参数说明

```
target                目标 URL
-t, --threads N       线程数（默认10）
--timeout N           超时秒数（默认10）
--cookie STR          Cookie字符串
--header K:V          自定义请求头（可多次）
--proxy URL           代理地址
--wordlist FILE       自定义目录字典

-o, --output FILE     JSON报告路径
--html FILE           HTML报告路径

--fast                快速模式
--only MODULES        只运行指定模块（逗号分隔）
--skip-ports          跳过端口扫描
--skip-dirbust        跳过目录枚举
--skip-sqli           跳过SQL注入
--skip-xss            跳过XSS
--skip-lfi            跳过LFI
--skip-subdomain      跳过子域名枚举
--skip-bruteforce     跳过弱口令检测
--skip-upload         跳过文件上传检测
```

---

## 项目结构

```
webscanner/
├── main.py
├── requirements.txt
├── README.md
├── core/
│   ├── colors.py       # Banner（作者: 火柴）、日志
│   ├── result.py       # 结果收集
│   └── scanner.py      # 基础扫描器
├── modules/            # 23 个扫描模块
│   ├── info.py         ├── cors.py
│   ├── headers.py      ├── csrf.py
│   ├── ssl_check.py    ├── clickjacking.py
│   ├── sensitive.py    ├── http_methods.py
│   ├── sqli.py         ├── jwt_check.py
│   ├── xss.py          ├── injections.py
│   ├── lfi.py          ├── api_security.py
│   ├── redirect.py     ├── xxe.py
│   ├── ssrf.py         ├── subdomain.py
│   ├── path_traversal.py├── file_upload.py
│   ├── weak_creds.py   ├── ports.py
│   └── dirbust.py
└── utils/
    ├── http.py         # HTTP工具
    └── report.py       # 终端/JSON/HTML报告
```

---

## 法律声明

本工具仅供安全研究人员、渗透测试工程师在**已获得书面授权**的情况下使用。  
对未授权目标使用本工具可能违反《中华人民共和国网络安全法》及其他相关法律。  
作者不承担任何因滥用本工具而产生的法律责任。

---

**Author: 火柴 | GitHub: https://github.com/huocai250**
