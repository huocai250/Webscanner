"""
扫描结果收集与管理
Author: 火柴 | GitHub: huocai250
v4.0: 增加自动去重、风险评分、置信度字段
"""
import threading
from datetime import datetime
from typing import List, Dict, Optional


# 各等级用于风险评分的权重
SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 8,
    "LOW": 2,
    "INFO": 0,
}


class Finding:
    def __init__(self, category: str, severity: str, detail: str,
                 evidence: str = "", url: str = "", confidence: str = "确认"):
        self.category = category
        self.severity = severity.upper()
        self.detail = detail
        self.evidence = evidence
        self.url = url
        self.confidence = confidence          # 确认 / 疑似 / 信息
        self.time = datetime.now().isoformat()

    def key(self):
        """用于去重的唯一键。"""
        return (self.category, self.severity, self.detail, self.url)

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
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
        self.end_time: Optional[datetime] = None
        self.findings: List[Finding] = []
        self._seen = set()
        self._lock = threading.Lock()
        self.request_count = 0                # 统计发出的请求数

    def add(self, category: str, severity: str, detail: str,
            evidence: str = "", url: str = "", confidence: str = "确认") -> bool:
        """添加一条发现；重复项自动忽略。返回是否新增。"""
        finding = Finding(category, severity, detail, evidence, url, confidence)
        with self._lock:
            if finding.key() in self._seen:
                return False
            self._seen.add(finding.key())
            self.findings.append(finding)
        return True

    def incr_requests(self, n: int = 1):
        with self._lock:
            self.request_count += n

    def finish(self):
        self.end_time = datetime.now()

    def summary(self) -> Dict[str, int]:
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def by_severity(self, severity: str) -> List[Finding]:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        items = [f for f in self.findings if f.severity == severity]
        return sorted(items, key=lambda f: (f.category, f.url))

    def risk_score(self) -> int:
        """0–100 的综合风险评分。"""
        raw = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in self.findings)
        return min(100, raw)

    def risk_grade(self) -> str:
        s = self.risk_score()
        if s >= 70:
            return "严重"
        if s >= 40:
            return "高危"
        if s >= 15:
            return "中危"
        if s > 0:
            return "低危"
        return "良好"

    def elapsed(self) -> str:
        end = self.end_time or datetime.now()
        delta = end - self.start_time
        return f"{delta.total_seconds():.1f}s"
