"""
GraphQL 检测模块（新增）
Author: 火柴 | GitHub: huocai250
探测常见 GraphQL 端点并检测 introspection 是否对外开放（常见生产配置错误）
"""
from core.scanner import BaseScanner
from core.colors import log

ENDPOINTS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
             "/query", "/graphql/console", "/gql"]

# 极简 introspection 查询
INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}


class GraphQLScanner(BaseScanner):
    name = "graphql"
    passive = True

    def run(self):
        log("INFO", "GraphQL introspection 检测...")
        for ep in ENDPOINTS:
            url = self.url(ep)
            r = self.post(url, json=INTROSPECTION_QUERY)
            if not r:
                continue
            body = (r.text or "")[:2000]
            if "__schema" in body and ("queryType" in body or '"data"' in body):
                log("VULN", f"GraphQL introspection 开放: {ep}")
                self.add("GraphQL", "MEDIUM",
                         f"GraphQL introspection 对外开放: {ep}，可能暴露完整 API 结构",
                         url=url)
                return
            if '"errors"' in body and "graphql" in body.lower():
                # 端点存在但 introspection 可能被禁
                log("OK", f"发现 GraphQL 端点（introspection 似乎已禁用）: {ep}")
                self.add("GraphQL", "INFO",
                         f"发现 GraphQL 端点: {ep}", url=url, confidence="信息")
                return
