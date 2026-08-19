"""
子域名接管指纹检测模块（被动）
Author: 火柴 | GitHub: huocai250

检测目标是否指向「未认领的第三方服务」——若某服务的响应含特征性的
「无此站点/存储桶不存在」提示，说明该 CNAME 指向的资源可被攻击者注册接管
（子域名接管）。仅做指纹识别，不执行接管。
"""
from core.scanner import BaseScanner
from core.colors import log

# (服务名, 特征字符串列表) —— 命中即疑似可接管
FINGERPRINTS = [
    ("GitHub Pages", ["There isn't a GitHub Pages site here",
                      "For root URLs (like http://example.com/) you must provide an index"]),
    ("Amazon S3", ["NoSuchBucket", "The specified bucket does not exist"]),
    ("Heroku", ["No such app", "herokucdn.com/error-pages/no-such-app.html"]),
    ("Bitbucket", ["Repository not found", "The page you have requested does not exist"]),
    ("Fastly", ["Fastly error: unknown domain"]),
    ("Shopify", ["Sorry, this shop is currently unavailable"]),
    ("Tumblr", ["Whatever you were looking for doesn't currently exist at this address"]),
    ("Ghost", ["The thing you were looking for is no longer here"]),
    ("Surge.sh", ["project not found"]),
    ("Zendesk", ["Help Center Closed", "this help center no longer exists"]),
    ("Unbounce", ["The requested URL was not found on this server"]),
    ("AWS/ELB", ["<Code>NoSuchBucket</Code>"]),
    ("Pantheon", ["The gods are wise, but do not know of the site which you seek"]),
    ("Readthedocs", ["The link you have followed or the URL that you entered does not exist"]),
]


class TakeoverScanner(BaseScanner):
    name = "takeover"
    passive = True

    def run(self):
        log("INFO", "子域名接管指纹检测...")
        r = self.baseline(self.target)
        if not r:
            return
        body = r.text or ""
        for service, signs in FINGERPRINTS:
            if any(s in body for s in signs):
                log("VULN", f"[子域名接管] 疑似指向未认领的 {service}")
                self.add("配置错误", "HIGH",
                         f"目标疑似指向未认领的 {service} 资源，存在子域名接管风险",
                         evidence=f"命中 {service} 接管指纹", url=r.url,
                         confidence="疑似")
                return
