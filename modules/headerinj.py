"""
邮件头注入 / CSV 公式注入检测模块（主动）
Author: 火柴 | GitHub: huocai250

- HeaderInjectionScanner：向邮件相关参数注入换行，检测应用是否允许注入额外
  邮件头（可导致垃圾邮件/钓鱼）。带内通过错误特征/反射判断。
- CSVFormulaScanner：检测导出/表单字段是否会把 =,+,-,@ 开头的公式原样进入
  CSV 导出（Excel 公式注入/CSV Injection）。此处只做「反射进疑似导出内容」的
  轻量提示。
"""
import re
from core.scanner import BaseScanner
from core.colors import log
from utils.http import build_url

MAIL_PARAMS = ["email", "to", "from", "subject", "cc", "bcc", "sender",
               "reply_to", "mail", "recipient"]
HEADER_ERRORS = [
    r"Invalid header", r"header injection", r"mail\(\): Multiple or malformed",
    r"suspicious header", r"newline", r"header value must not contain",
]


class HeaderInjectionScanner(BaseScanner):
    name = "headerinj"
    passive = False

    def run(self):
        log("INFO", "邮件头注入检测（换行注入，并发）...")
        targets = self.injection_targets(MAIL_PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        for payload in ("test%0d%0aBcc:wvs@evil.example",
                        "test\r\nBcc:wvs@evil.example",
                        "test%0aCc:wvs@evil.example"):
            test = dict(params); test[pname] = payload
            r = self.post(url, data=test) if method == "POST" else self.get(build_url(url, test))
            if not r or not r.text:
                continue
            for sign in HEADER_ERRORS:
                if re.search(sign, r.text, re.I):
                    log("VULN", f"[邮件头注入] 参数 {pname}")
                    self.add("CRLF 注入", "MEDIUM",
                             f"邮件参数 '{pname}' 疑似头注入（换行触发头处理错误）",
                             evidence=f"payload 触发 '{sign}' @ {url}", url=url,
                             confidence="疑似")
                    return f"{pname}@{url}"
        return None


class CSVFormulaScanner(BaseScanner):
    name = "csvinj"
    passive = False

    CSV_PARAMS = ["name", "title", "comment", "note", "description", "value",
                  "field", "content", "message", "remark"]

    def run(self):
        log("INFO", "CSV 公式注入检测（导出字段反射，并发）...")
        targets = self.injection_targets(self.CSV_PARAMS)
        self.map(self._test, targets)

    def _test(self, target):
        url, method, params, pname = target
        marker = "=WVSCSV(1+1)"
        test = dict(params); test[pname] = marker
        if method == "POST":
            r = self.post(url, data=test)
        else:
            r = self.get(build_url(url, test))
        if not r:
            return None
        ctype = r.headers.get("Content-Type", "").lower()
        cdisp = r.headers.get("Content-Disposition", "").lower()
        is_export = ("csv" in ctype or "excel" in ctype or "spreadsheet" in ctype
                     or "attachment" in cdisp)
        # 若响应是导出文件且原样包含公式，则提示 CSV 注入风险
        if is_export and marker in (r.text or ""):
            log("VULN", f"[CSV注入] 参数 {pname}")
            self.add("配置错误", "MEDIUM",
                     f"参数 '{pname}' 的值以公式形式进入 CSV/表格导出，存在公式注入风险",
                     evidence=f"marker 原样出现在导出 @ {url}", url=url,
                     confidence="疑似")
            return f"{pname}@{url}"
        return None
