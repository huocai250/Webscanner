"""
扫描结果收集与管理
Author: 火柴 | GitHub: huocai250
"""
import threading
from datetime import datetime
from typing import List, Dict


class Finding:
    def __init__(self, category: str, severity: str, detail: str, evidence: str = "", url: str = ""):
        self.category = category
        self.severity = severity
        self.detail = detail
        self.evidence = evidence
        self.url = url
        self.time = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
            "url": self.url,
            "time": self.time,
        }


class ScanResult:
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def __init__(self, target: str):
        self.target = target
        self.start_time = datetime.now()
        self.findings: List[Finding] = []
        self._lock = threading.Lock()

    def add(self, category: str, severity: str, detail: str,
            evidence: str = "", url: str = ""):
        finding = Finding(category, severity, detail, evidence, url)
        with self._lock:
            self.findings.append(finding)

    def summary(self) -> Dict[str, int]:
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def elapsed(self) -> str:
        delta = datetime.now() - self.start_time
        return f"{delta.total_seconds():.1f}s"
