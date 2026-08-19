"""
API 文档/接口发现模块（被动）
Author: 火柴 | GitHub: huocai250

探测常见的 API 文档与接口描述端点（Swagger/OpenAPI/GraphQL/WSDL/API 版本根），
这些一旦对外暴露会显著扩大攻击面（暴露全部接口、参数、鉴权方式）。
仅做发现，不调用/滥用其中接口。
"""
from core.scanner import BaseScanner
from core.colors import log

# (path, 判定签名, severity, 说明)
API_ENDPOINTS = [
    ("/swagger.json", ["swagger", "openapi", "\"paths\""], "MEDIUM", "Swagger/OpenAPI 定义"),
    ("/openapi.json", ["openapi", "\"paths\""], "MEDIUM", "OpenAPI 定义"),
    ("/v2/api-docs", ["swagger", "\"paths\""], "MEDIUM", "Springfox Swagger 文档"),
    ("/v3/api-docs", ["openapi", "\"paths\""], "MEDIUM", "OpenAPI v3 文档"),
    ("/swagger-ui.html", ["Swagger UI", "swagger-ui"], "LOW", "Swagger UI 页面"),
    ("/swagger/index.html", ["Swagger UI", "swagger"], "LOW", "Swagger UI 页面"),
    ("/api-docs", ["swagger", "openapi"], "LOW", "API 文档"),
    ("/redoc", ["redoc", "ReDoc"], "LOW", "ReDoc API 文档"),
    ("/graphql", ["__schema", "\"data\"", "errors"], "MEDIUM", "GraphQL 端点"),
    ("/graphiql", ["graphiql", "GraphiQL"], "MEDIUM", "GraphiQL 交互界面"),
    ("/api/swagger.json", ["swagger", "openapi"], "MEDIUM", "Swagger 定义"),
    ("/services?wsdl", ["wsdl:definitions", "<definitions"], "MEDIUM", "SOAP WSDL"),
    ("/soap?wsdl", ["wsdl:definitions", "<definitions"], "MEDIUM", "SOAP WSDL"),
    ("/api/", ["\"version\"", "\"api\"", "\"data\""], "INFO", "API 根"),
    ("/.well-known/openid-configuration", ["issuer", "authorization_endpoint"],
     "INFO", "OpenID 配置"),
]


class APIDocsScanner(BaseScanner):
    name = "apidocs"
    passive = True

    def run(self):
        log("INFO", "API 文档/接口发现...")
        found = self.map(self._check, API_ENDPOINTS)
        if not found:
            log("INFO", "  未发现暴露的 API 文档端点")

    def _check(self, entry):
        path, signs, sev, desc = entry
        r = self.get(self.url(path))
        if not r or r.status_code not in (200, 401, 403):
            return None
        blob = (r.text or "")[:20000]
        if r.status_code == 200 and any(s in blob for s in signs):
            log("VULN", f"[API 发现] {desc}: {path}")
            self.add("信息泄露", sev,
                     f"{desc} 暴露: {path}（扩大攻击面，暴露接口/参数/鉴权）",
                     evidence=f"HTTP 200 @ {path}", url=r.url,
                     confidence="确认" if sev != "INFO" else "信息")
            return path
        return None
