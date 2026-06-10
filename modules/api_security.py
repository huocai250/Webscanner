"""
API 安全检测模块
Author: 火柴 | GitHub: huocai250

修复:
- post 改用 json_data 参数（避免与内置 json 冲突）
- GraphQL introspection 改用 json_data 发送
- 改进 IDOR 检测避免误报
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")


import json
from core.scanner import BaseScanner

API_ENDPOINTS = [
    "/api/users", "/api/user", "/api/v1/users", "/api/v2/users",
    "/api/admin", "/api/v1/admin", "/api/config", "/api/settings",
    "/api/keys", "/api/tokens", "/api/health", "/api/debug",
    "/api/v1/me", "/api/v2/me", "/api/profile",
    "/api/v1/products", "/api/v1/orders",
    "/rest/user", "/rest/admin",
    "/api/swagger.json", "/api/openapi.json",
    "/v1/users", "/v2/users", "/v1/admin",
    "/actuator", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/health",
    "/actuator/info", "/actuator/logfile",
    "/graphql", "/api/graphql", "/graphiql", "/playground",
]

SENSITIVE_KEYS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "auth_token", "private_key", "credit_card",
    "ssn", "social_security",
]

GRAPHQL_QUERY = {"query": "{ __schema { types { name fields { name } } } }"}

IDOR_TEMPLATES = [
    "/api/user/{id}", "/api/users/{id}",
    "/api/v1/user/{id}", "/api/order/{id}",
]


class APIScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        r = self.get(self.build_url("__ws_api_nx_ref__"))
        self._soft404_len = len(r.text) if r else 0

    def run(self):
        log.info( "API 安全检测（未授权访问 / GraphQL / IDOR）...")
        self._scan_endpoints()
        self._test_graphql()
        self._test_idor()

    def _scan_endpoints(self):
        for path in API_ENDPOINTS:
            url = self.build_url(path)
            r   = self.get(url)
            if not r or r.status_code not in [200, 201]:
                continue
            ct = r.headers.get("Content-Type", "")
            body = r.text.strip()
            is_json = "json" in ct or body.startswith(("{", "["))
            if not is_json:
                continue
            # 软404过滤
            if self._soft404_len > 0 and abs(len(r.text) - self._soft404_len) < 100:
                continue

            log.warning( f"[API] 未授权可访问: {url}")
            severity = "HIGH"
            if self._has_sensitive(body):
                severity = "CRITICAL"
                log.warning("[VULN] " +  f"[API] 含敏感数据: {url}")
            self.result.add("API 未授权", severity,
                            f"API 端点未授权可访问: {path}",
                            body[:200], url=url)

    def _test_graphql(self):
        for path in ["/graphql", "/api/graphql", "/graphiql"]:
            url = self.build_url(path)
            # 修复: 使用 json_data 参数
            r = self.post(url, json_data=GRAPHQL_QUERY,
                          extra_headers={"Content-Type": "application/json"})
            if not r:
                continue
            if r.status_code == 200 and "__schema" in r.text:
                log.warning("[VULN] " +  f"[GraphQL] Introspection 已启用: {url}")
                self.result.add("GraphQL", "MEDIUM",
                                "GraphQL Introspection 已启用，暴露完整 Schema",
                                url=url)
                return

    def _test_idor(self):
        for template in IDOR_TEMPLATES:
            found_count = 0
            for id_val in ["1", "2", "3", "100"]:
                path = template.replace("{id}", id_val)
                url  = self.build_url(path)
                r    = self.get(url)
                if r and r.status_code == 200:
                    ct = r.headers.get("Content-Type", "")
                    if "json" in ct or r.text.strip().startswith(("{", "[")):
                        found_count += 1
            # 如果连续多个 ID 都可访问，疑似 IDOR
            if found_count >= 3:
                log.warning("[VULN] " +  f"[IDOR] 多个 ID 均可访问: {template}")
                self.result.add("IDOR", "HIGH",
                                f"可能存在 IDOR：连续 {found_count} 个 ID 均可未授权访问",
                                url=self.build_url(template.replace("{id}", "1")))
                return

    def _has_sensitive(self, text: str) -> bool:
        tl = text.lower()
        return any(k in tl for k in SENSITIVE_KEYS)
