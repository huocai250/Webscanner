"""
按类别提供修复建议（用于报告输出）
Author: 火柴 | GitHub: huocai250
v4.0 新增：让报告不仅指出问题，还告诉用户如何修
"""

REMEDIATION = {
    "SQL 注入":
        "使用参数化查询/预编译语句（Prepared Statement），对所有用户输入做类型校验与转义；"
        "遵循最小权限原则配置数据库账号，关闭详细报错回显。",
    "XSS":
        "对输出到 HTML/JS/属性上下文的数据做相应编码；启用严格的 Content-Security-Policy；"
        "对富文本使用成熟的白名单过滤库（如 DOMPurify）。",
    "SSTI":
        "避免将用户输入拼接进模板；使用沙箱化模板引擎或逻辑更弱的模板；"
        "对必须动态渲染的内容做严格白名单校验。",
    "文件包含":
        "禁止使用用户输入直接拼接文件路径；使用白名单映射文件；"
        "关闭 PHP allow_url_include/allow_url_fopen，规范化并校验路径。",
    "命令注入":
        "避免调用系统 shell；如必须执行命令，使用参数数组形式（不经 shell 解析）"
        "并对参数做严格白名单校验。",
    "开放重定向":
        "重定向目标使用服务端白名单或相对路径；对 URL 参数做协议与主机校验，"
        "拒绝跨站跳转。",
    "CORS":
        "避免反射任意 Origin；使用明确的白名单；除非必要不要同时设置 "
        "Access-Control-Allow-Credentials: true 与宽松 Origin。",
    "CSRF":
        "为所有状态变更请求加入不可预测的 CSRF Token 并在服务端校验；"
        "配合 SameSite=Lax/Strict Cookie 与关键操作二次确认。",
    "安全头缺失":
        "补全 HSTS、CSP、X-Frame-Options、X-Content-Type-Options 等安全响应头，"
        "可在反向代理或应用中间件统一注入。",
    "Cookie 安全":
        "为敏感 Cookie 设置 Secure、HttpOnly、SameSite 属性，避免通过脚本读取或明文传输。",
    "SSL/TLS":
        "使用有效且未过期的证书；禁用 SSLv3/TLS1.0/TLS1.1，仅保留 TLS1.2+ 并配置强加密套件；"
        "开启 OCSP Stapling 与 HSTS。",
    "敏感信息泄露":
        "从公开响应/源码中移除密钥、凭据与内部信息；轮换已泄露的密钥；"
        "使用密钥管理服务，禁止将 .env/.git 等部署到 Web 根目录。",
    "文件暴露":
        "禁止对外访问 .git、.env、备份文件等；在 Web 服务器层拒绝隐藏文件与备份后缀；"
        "从生产环境清理调试/信息页面。",
    "信息泄露":
        "移除或伪装 Server、X-Powered-By 等暴露版本的响应头，减少指纹信息。",
    "HTTP 方法":
        "关闭不必要的 HTTP 方法（PUT/DELETE/TRACE 等）；禁用 WebDAV；"
        "在服务器与应用层限制允许的方法。",
    "GraphQL":
        "生产环境关闭 GraphQL introspection；限制查询深度/复杂度；对字段做鉴权。",
    "Host 头注入":
        "不要信任 Host/X-Forwarded-Host 头；使用固定的规范域名生成链接与重置邮件；"
        "在服务器层校验 Host。",
    "端口扫描":
        "关闭对外暴露的高危服务端口；数据库/中间件绑定内网并启用认证；"
        "使用防火墙与安全组限制访问来源。",
    "目录枚举":
        "移除或保护后台、备份、调试路径；对敏感路径加认证；"
        "关闭目录列表；对不存在资源返回统一 404。",
    "JWT 安全":
        "禁用 alg=none；服务端固定校验算法，避免算法混淆；使用足够强度的密钥"
        "（或改用非对称 RS/ES）；设置合理的 exp；不要在 payload 放敏感信息。",
    "CRLF 注入":
        "对写入响应头的用户输入过滤/编码 \\r\\n；使用框架安全的重定向/头设置 API；"
        "拒绝含控制字符的输入。",
    "路径穿越":
        "对文件路径做白名单/规范化校验，禁止 ../ 与编码变体；使用安全的文件访问 API；"
        "以最小权限运行并限制可访问目录。",
    "XXE 注入":
        "禁用 XML 外部实体与 DTD 解析（如 disallow-doctype-decl、"
        "FEATURE_SECURE_PROCESSING）；优先使用 JSON；对上传的 XML 做严格限制。",
    "SSRF":
        "对用户可控的 URL/主机做白名单校验；禁止访问内网与云元数据地址；"
        "在网络层隔离出站请求；解析后再校验最终地址，防 DNS 重绑定。",
    "Log4Shell":
        "升级 Log4j 到安全版本（2.17.1+）；移除 JndiLookup 类或设置"
        "log4j2.formatMsgNoLookups=true；对入站数据做校验并限制出站访问。",
    "点击劫持":
        "设置 X-Frame-Options: DENY/SAMEORIGIN，或使用 CSP frame-ancestors；"
        "对敏感操作增加二次确认。",
    "配置错误":
        "关闭调试模式与详细报错；移除默认/示例页面；对管理入口加认证与访问限制；"
        "遵循最小暴露原则。",
    "NoSQL 注入":
        "使用参数化查询/ODM，避免把用户输入拼进查询对象；对输入做类型与结构校验；"
        "禁止将字符串直接作为查询运算符。",
    "LDAP 注入":
        "对 LDAP 过滤器中的特殊字符转义（\\、*、(、) 等）；使用安全的 LDAP API 与参数化；"
        "最小化目录查询权限。",
    "XPath 注入":
        "使用参数化 XPath（变量绑定）而非字符串拼接；对输入做白名单校验；"
        "考虑改用更安全的数据访问方式。",
    "SSI 注入":
        "关闭不需要的 SSI；对写入页面的用户输入转义 <!--#；避免在可被用户控制的内容上启用 SSI。",
}

DEFAULT_REMEDIATION = "参考 OWASP 相关指南，对该问题进行修复与复测。"


def get(category: str) -> str:
    return REMEDIATION.get(category, DEFAULT_REMEDIATION)
