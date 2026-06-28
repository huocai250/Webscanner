"""
HTTP 工具函数 — WebVulnScanner v6.0
Author: 火柴 | GitHub: huocai250

[优化] 改进命名、增加类型注解
[新增] extract_all_urls / normalize_url
"""
import re
from urllib.parse import urlparse, urljoin, urlencode
from typing import List, Dict


def extract_forms(html: str) -> List[Dict]:
    """提取页面所有表单及其字段"""
    forms = []
    for fm in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.S | re.I):
        attrs_str, body = fm.groups()
        method = re.search(r'method=["\'](\w+)["\']', attrs_str, re.I)
        action = re.search(r'action=["\']([^"\']*)["\']', attrs_str, re.I)
        inputs = re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
            body, re.I)
        # [新增] 也提取 textarea 和 select
        textareas = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', body, re.I)
        form_inputs = {name: (val or "test") for name, val in inputs}
        for ta in textareas:
            form_inputs[ta] = "test"
        forms.append({
            "method": method.group(1).upper() if method else "GET",
            "action": action.group(1) if action else "",
            "inputs": form_inputs,
        })
    return forms


def extract_links(html: str, base_url: str) -> List[str]:
    """提取页面所有同源链接"""
    hrefs = re.findall(r'href=["\']([^"\'#?][^"\']*)["\']', html, re.I)
    links = []
    base_netloc = urlparse(base_url).netloc
    for h in hrefs:
        if h.startswith(("mailto:", "tel:", "javascript:")):
            continue
        full = urljoin(base_url, h)
        if urlparse(full).netloc == base_netloc:
            links.append(full.split("#")[0])   # 去掉锚点
    return list(dict.fromkeys(links))           # 去重保序


def extract_all_urls(html: str, base_url: str) -> List[str]:
    """[新增] 提取页面所有 URL（含 src / action / data-url 等）"""
    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
        r'data-url=["\']([^"\']+)["\']',
        r'url\(["\']?([^"\')\s]+)["\']?\)',
    ]
    urls = []
    base_netloc = urlparse(base_url).netloc
    for pat in patterns:
        for m in re.findall(pat, html, re.I):
            full = urljoin(base_url, m)
            if urlparse(full).netloc == base_netloc:
                urls.append(full.split("#")[0])
    return list(dict.fromkeys(urls))


def extract_params(html: str) -> Dict[str, str]:
    """从页面 input 提取参数名"""
    names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I)
    return {n: "test" for n in names}


def parse_cookies(cookie_str: str) -> Dict[str, str]:
    """解析 Cookie 字符串"""
    cookies = {}
    for part in (cookie_str or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def parse_headers(header_list: List[str]) -> Dict[str, str]:
    """[新增] 解析 ['K:V', 'K2:V2'] 格式的请求头列表"""
    headers = {}
    for h in (header_list or []):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def normalize_url(url: str) -> str:
    """[新增] URL 规范化：去空格、补全协议、去尾部多余斜杠"""
    url = url.strip()                               # 去首尾空格
    if not url:
        return url
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    # 去尾部多余斜杠（保留单个斜杠路径）
    parsed = url.rstrip("/")
    return parsed
