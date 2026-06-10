"""
扫描结果收集模块 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

[优化] 增加 exploit_result 字段存储利用结果
       增加 to_csv_row() 方法
       改进线程安全
"""
import threading
from datetime import datetime
from typing import List, Dict, Optional


class Finding:
    """单条漏洞发现记录"""

    SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def __init__(
        self,
        category:       str,
        severity:       str,
        detail:         str,
        evidence:       str  = "",
        url:            str  = "",
        exploit_result: str  = "",   # [新增] 漏洞利用结果
        extra:          Dict = None, # [新增] 额外信息（如 dump 的数据）
    ):
        self.category       = category
        self.severity       = severity.upper()
        self.detail         = detail
        self.evidence       = evidence
        self.url            = url
        self.exploit_result = exploit_result
        self.extra          = extra or {}
        self.timestamp      = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            "category":       self.category,
            "severity":       self.severity,
            "detail":         self.detail,
            "evidence":       self.evidence,
            "url":            self.url,
            "exploit_result": self.exploit_result,
            "extra":          self.extra,
            "timestamp":      self.timestamp,
        }

    def to_csv_row(self) -> List[str]:
        """[新增] CSV 行数据"""
        return [
            self.timestamp,
            self.severity,
            self.category,
            self.detail,
            self.url,
            self.evidence[:200],
            self.exploit_result[:500],
        ]

    def __lt__(self, other):
        """按严重性排序"""
        return (self.SEVERITY_RANK.get(self.severity, 99) <
                self.SEVERITY_RANK.get(other.severity, 99))


class ScanResult:
    """扫描结果容器，线程安全"""

    SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def __init__(self, target: str):
        self.target     = target
        self.start_time = datetime.now()
        self.findings:  List[Finding] = []
        self._lock      = threading.Lock()

    def add(
        self,
        category:       str,
        severity:       str,
        detail:         str,
        evidence:       str  = "",
        url:            str  = "",
        exploit_result: str  = "",
        extra:          Dict = None,
    ):
        """[优化] 统一的结果添加入口，线程安全"""
        finding = Finding(category, severity, detail, evidence, url,
                          exploit_result, extra)
        with self._lock:
            self.findings.append(finding)

    def summary(self) -> Dict[str, int]:
        counts = {s: 0 for s in self.SEVERITIES}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def sorted_findings(self) -> List[Finding]:
        """按严重性从高到低排序"""
        return sorted(self.findings)

    def elapsed(self) -> str:
        delta = datetime.now() - self.start_time
        secs  = int(delta.total_seconds())
        return f"{secs // 60}m{secs % 60}s" if secs >= 60 else f"{secs}s"

    def total(self) -> int:
        return len(self.findings)
