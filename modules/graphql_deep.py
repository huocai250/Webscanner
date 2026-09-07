"""
GraphQL 深度检测 / JWT 高级分析模块（被动 / 仅分析）
Author: 火柴 | GitHub: huocai250
"""
import re
import json
import base64
from core.scanner import BaseScanner
from core.colors import log

GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"]


class GraphQLDeepScanner(BaseScanner):
    name = "graphqldeep"
    passive = True

    def run(self):
        log("INFO", "GraphQL 深度检测（建议泄露/批量/GET 查询）...")
        endpoint = self._find()
        if not endpoint:
            log("INFO", "  未发现 GraphQL 端点")
            return
        self._suggestions(endpoint)
        self._get_query(endpoint)
        self._batching(endpoint)

    def _find(self):
        for p in GQL_PATHS:
            r = self.post(self.url(p), json={"query": "{__typename}"})
            if r and ("__typename" in (r.text or "") or "errors" in (r.text or "")
                      and "query" in (r.text or "").lower()):
                return self.url(p)
        return None

    def _suggestions(self, ep):
        # 字段拼写建议会泄露 schema，即使 introspection 关闭
        r = self.post(ep, json={"query": "{ __schemaa }"})
        if r and re.search(r'Did you mean ["\']?__schema', r.text or "", re.I):
            self.add("GraphQL", "MEDIUM",
                     "GraphQL 开启了字段建议（Did you mean），即使关闭 introspection 也会泄露 schema",
                     evidence=ep, url=ep, confidence="疑似")
            log("VULN", "[GraphQL] 字段建议泄露 schema")

    def _get_query(self, ep):
        # GET 方式可执行查询 => 可能被 CSRF 利用
        r = self.get(ep + "?query=%7B__typename%7D")
        if r and "__typename" in (r.text or ""):
            self.add("GraphQL", "LOW",
                     "GraphQL 允许通过 GET 执行查询，可能被 CSRF 滥用",
                     evidence=ep, url=ep, confidence="疑似")

    def _batching(self, ep):
        r = self.post(ep, json=[{"query": "{__typename}"}, {"query": "{__typename}"}])
        if r and (r.text or "").count("__typename") >= 2:
            self.add("GraphQL", "LOW",
                     "GraphQL 支持查询批处理（array），可被用于放大暴力破解",
                     evidence=ep, url=ep, confidence="疑似")


class JWTAdvancedScanner(BaseScanner):
    name = "jwtadv"
    passive = True

    def run(self):
        from modules.jwt_check import JWT_RE, _b64d
        log("INFO", "JWT 高级分析（kid/jku/x5u/算法混淆，静态）...")
        tokens = []
        for v in list(self.config.cookies.values()) + list(self.config.headers.values()):
            tokens += JWT_RE.findall(str(v))
        r = self.baseline(self.target)
        if r:
            blob = " ".join(f"{k}: {v}" for k, v in r.headers.items()) + (r.text or "")
            tokens += JWT_RE.findall(blob)
        seen = set()
        for tok in tokens:
            if tok in seen:
                continue
            seen.add(tok)
            self._analyze_header(tok, _b64d)

    def _analyze_header(self, tok, b64d):
        try:
            header = json.loads(b64d(tok.split(".")[0]) or b"{}")
        except Exception:
            return
        # kid 注入面
        if "kid" in header:
            self.add("JWT 安全", "LOW",
                     "JWT 头含 kid 参数：若服务端用其拼接文件路径/SQL，存在注入/路径穿越面",
                     evidence=f"kid={header.get('kid')}", url=self.target, confidence="信息")
        # jku / x5u 远程取密钥
        for f in ("jku", "x5u"):
            if f in header:
                self.add("JWT 安全", "MEDIUM",
                         f"JWT 头含 {f}（远程密钥 URL）：若未严格校验来源，可被伪造签名密钥",
                         evidence=f"{f}={header.get(f)}", url=self.target, confidence="疑似")
                log("VULN", f"[JWT] 头含 {f}")
        # 算法混淆提示（RS -> HS）
        alg = str(header.get("alg", "")).upper()
        if alg.startswith("RS") or alg.startswith("ES"):
            self.add("JWT 安全", "LOW",
                     f"JWT 使用非对称算法 {alg}：需确认服务端未接受把公钥当 HMAC 密钥（算法混淆）",
                     evidence=f"alg={alg}", url=self.target, confidence="信息")
