"""
HTTP 工具函数
Author: 火柴 | GitHub: huocai250
"""
import re
from urllib.parse import urlparse, urljoin


def extract_forms(html: str) -> list[dict]:
    """提取页面中所有表单及其字段"""
    forms = []
    for form_match in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.S | re.I):
        attrs_str, body = form_match.groups()
        method = re.search(r'method=["\'](\w+)["\']', attrs_str, re.I)
        action = re.search(r'action=["\']([^"\']*)["\']', attrs_str, re.I)
        inputs = re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
            body, re.I)
        forms.append({
            "method": method.group(1).upper() if method else "GET",
            "action": action.group(1) if action else "",
            "inputs": {name: val or "test" for name, val in inputs},
        })
    return forms


def extract_links(html: str, base_url: str) -> list[str]:
    """提取页面中所有链接"""
    hrefs = re.findall(r'href=["\']([^"\'#]+)["\']', html, re.I)
    links = []
    for h in hrefs:
        full = urljoin(base_url, h)
        if urlparse(full).netloc == urlparse(base_url).netloc:
            links.append(full)
    return list(set(links))


def extract_params(html: str) -> dict:
    """从页面提取输入参数名"""
    names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I)
    return {n: "test" for n in names}


def parse_cookies(cookie_str: str) -> dict:
    """解析 Cookie 字符串"""
    cookies = {}
    for part in (cookie_str or "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies
