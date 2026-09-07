"""
指纹识别模块（被动）
Author: 火柴 | GitHub: huocai250

从响应头 / Cookie / 正文 / meta / 特定路径被动识别目标技术栈：
CMS、Web 框架、服务器、CDN、WAF、开发语言、数据库等。
结果写入 ScanContext.fingerprints，供 CMS 专项等模块消费。
"""
import re
from core.scanner import BaseScanner
from core.colors import log

# 规则：(名称, 类别, 匹配位置, 正则)
# 匹配位置: header:<名> / cookie / body / meta-generator / any-header
FINGERPRINTS = [
    # ---- 服务器 ----
    ("Nginx", "服务器", "header:server", r"nginx"),
    ("Apache", "服务器", "header:server", r"apache"),
    ("IIS", "服务器", "header:server", r"microsoft-iis"),
    ("LiteSpeed", "服务器", "header:server", r"litespeed"),
    ("Tomcat", "服务器", "header:server", r"(tomcat|coyote)"),
    ("Jetty", "服务器", "header:server", r"jetty"),
    ("OpenResty", "服务器", "header:server", r"openresty"),
    ("Gunicorn", "服务器", "header:server", r"gunicorn"),
    ("Kestrel", "服务器", "header:server", r"kestrel"),
    # ---- 开发语言 ----
    ("PHP", "语言", "header:x-powered-by", r"php"),
    ("PHP", "语言", "header:set-cookie", r"phpsessid"),
    ("ASP.NET", "语言", "header:x-powered-by", r"asp\.net"),
    ("ASP.NET", "语言", "header:x-aspnet-version", r".+"),
    ("ASP.NET", "语言", "header:set-cookie", r"asp\.net_sessionid"),
    ("Java", "语言", "header:set-cookie", r"jsessionid"),
    ("Python", "语言", "header:x-powered-by", r"(python|werkzeug|flask)"),
    ("Node.js", "语言", "header:x-powered-by", r"express"),
    ("Ruby", "语言", "header:x-powered-by", r"(phusion|passenger)"),
    # ---- Web 框架 ----
    ("Express", "框架", "header:x-powered-by", r"express"),
    ("Django", "框架", "header:set-cookie", r"(csrftoken|django)"),
    ("Flask", "框架", "header:server", r"werkzeug"),
    ("Laravel", "框架", "header:set-cookie", r"laravel_session"),
    ("Ruby on Rails", "框架", "header:set-cookie", r"_rails|_session_id"),
    ("Spring Boot", "框架", "any-header", r"x-application-context"),
    ("ThinkPHP", "框架", "header:x-powered-by", r"thinkphp"),
    ("Symfony", "框架", "header:set-cookie", r"symfony"),
    ("Next.js", "框架", "any-header", r"x-nextjs"),
    ("ASP.NET MVC", "框架", "any-header", r"x-aspnetmvc-version"),
    # ---- CMS ----
    ("WordPress", "CMS", "meta-generator", r"wordpress"),
    ("WordPress", "CMS", "body", r"/wp-(content|includes|json)/"),
    ("Joomla", "CMS", "meta-generator", r"joomla"),
    ("Joomla", "CMS", "body", r"/media/jui/|option=com_"),
    ("Drupal", "CMS", "meta-generator", r"drupal"),
    ("Drupal", "CMS", "any-header", r"x-drupal-cache|x-generator.*drupal"),
    ("Magento", "CMS", "body", r"(mage/|magento|/static/version)"),
    ("Shopify", "CMS", "any-header", r"x-shopify"),
    ("DedeCMS", "CMS", "body", r"/dede/|dedecms|power by dede"),
    ("Discuz", "CMS", "body", r"(discuz|content=\"discuz)"),
    ("Typecho", "CMS", "meta-generator", r"typecho"),
    ("Ghost", "CMS", "meta-generator", r"ghost"),
    # ---- CDN / WAF ----
    ("Cloudflare", "CDN", "any-header", r"cf-ray|__cfduid|cloudflare"),
    ("Akamai", "CDN", "any-header", r"akamai|x-akamai"),
    ("Fastly", "CDN", "any-header", r"fastly|x-served-by.*cache"),
    ("CloudFront", "CDN", "any-header", r"cloudfront|x-amz-cf-id"),
    ("阿里云 CDN", "CDN", "any-header", r"(ali-swift|x-swift|via.*aliyun)"),
    ("Cloudflare WAF", "WAF", "any-header", r"cf-ray"),
    ("ModSecurity", "WAF", "any-header", r"mod_security|modsecurity"),
    ("Sucuri WAF", "WAF", "any-header", r"sucuri|x-sucuri"),
    ("Wallarm WAF", "WAF", "any-header", r"wallarm"),
    ("Safedog 安全狗", "WAF", "any-header", r"safedog"),
    ("Yundun 云盾", "WAF", "any-header", r"yunsuo|yundun"),
    # ---- 分析/其他 ----
    ("Google Analytics", "分析", "body", r"google-analytics\.com|gtag\("),
    ("jQuery", "前端库", "body", r"jquery[.-]?\d|jquery\.min\.js"),
    ("React", "前端库", "body", r"react(\.min)?\.js|data-reactroot"),
    ("Vue.js", "前端库", "body", r"vue(\.min)?\.js|data-v-"),
    ("Bootstrap", "前端库", "body", r"bootstrap(\.min)?\.(css|js)"),
    # ---- 更多服务器/中间件 ----
    ("Caddy", "服务器", "header:server", r"caddy"),
    ("Traefik", "服务器", "any-header", r"traefik"),
    ("Envoy", "服务器", "header:server", r"envoy"),
    ("uvicorn", "服务器", "header:server", r"uvicorn"),
    ("WEBrick", "服务器", "header:server", r"webrick"),
    ("Cowboy", "服务器", "header:server", r"cowboy"),
    ("Undertow", "服务器", "header:server", r"undertow"),
    ("WildFly", "服务器", "any-header", r"wildfly|jboss"),
    ("Zope", "服务器", "header:server", r"zope"),
    # ---- 更多框架/语言 ----
    ("FastAPI", "框架", "body", r"swagger-ui|/openapi\.json"),
    ("Gin", "框架", "any-header", r"gin"),
    ("CodeIgniter", "框架", "header:set-cookie", r"ci_session"),
    ("CakePHP", "框架", "header:set-cookie", r"cakephp"),
    ("Yii", "框架", "header:set-cookie", r"(yii|_csrf)"),
    ("Zend/Laminas", "框架", "header:set-cookie", r"z[df]sessid|laminas"),
    ("Phoenix", "框架", "header:set-cookie", r"_.*_key.*phoenix|phx"),
    ("Meteor", "框架", "body", r"__meteor_runtime_config__"),
    ("Angular", "前端库", "body", r"ng-version|angular(\.min)?\.js"),
    ("Svelte", "前端库", "body", r"svelte-[a-z0-9]{6}"),
    ("Nuxt", "框架", "body", r"__nuxt|nuxt\.js"),
    ("Gatsby", "框架", "body", r"___gatsby|gatsby-"),
    # ---- 更多 CMS ----
    ("PrestaShop", "CMS", "body", r"prestashop|/modules/ps_"),
    ("OpenCart", "CMS", "body", r"route=common|opencart"),
    ("Sitecore", "CMS", "any-header", r"sitecore|sc_"),
    ("AEM", "CMS", "body", r"/etc/designs|/etc\.clientlibs|granite"),
    ("Liferay", "CMS", "any-header", r"liferay"),
    ("Confluence", "CMS", "body", r"confluence|com\.atlassian"),
    ("MediaWiki", "CMS", "meta-generator", r"mediawiki"),
    ("phpBB", "CMS", "body", r"phpbb|/styles/prosilver"),
    ("vBulletin", "CMS", "body", r"vbulletin|vB_"),
    ("Craft CMS", "CMS", "header:set-cookie", r"craftsessionid"),
    ("Umbraco", "CMS", "body", r"umbraco"),
    ("Strapi", "CMS", "any-header", r"strapi"),
    # ---- 更多 WAF / CDN ----
    ("AWS WAF", "WAF", "any-header", r"awselb|x-amzn|aws-waf"),
    ("F5 BIG-IP", "WAF", "any-header", r"bigip|f5-|ts[0-9a-f]{8}="),
    ("Imperva", "WAF", "any-header", r"incap_ses|visid_incap|imperva"),
    ("Barracuda", "WAF", "any-header", r"barra_counter|barracuda"),
    ("Fortinet", "WAF", "any-header", r"fortiwafsid|fortigate"),
    ("Citrix NetScaler", "WAF", "any-header", r"ns_af|citrix_ns_id|netscaler"),
    ("KeyCDN", "CDN", "any-header", r"keycdn"),
    ("StackPath", "CDN", "any-header", r"stackpath"),
    ("Azure CDN", "CDN", "any-header", r"x-azure-ref|x-msedge-ref"),
]


class Fingerprinter(BaseScanner):
    name = "fingerprint"
    passive = True

    def run(self):
        log("INFO", "指纹识别（服务器/框架/CMS/CDN/WAF）...")
        r = self.baseline(self.target)
        if not r:
            log("WARN", "无法获取响应，跳过指纹识别")
            return

        headers = {k.lower(): v for k, v in r.headers.items()}
        # set-cookie 可能有多个，合并
        set_cookie = " ".join(v for k, v in r.headers.items()
                              if k.lower() == "set-cookie")
        if set_cookie:
            headers["set-cookie"] = set_cookie
        header_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
        body = r.text or ""
        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                        body, re.I)
        generator = gen.group(1) if gen else ""

        for name, cat, where, pattern in FINGERPRINTS:
            hay = ""
            if where.startswith("header:"):
                hay = headers.get(where.split(":", 1)[1], "")
            elif where == "any-header":
                hay = header_blob
            elif where == "cookie":
                hay = headers.get("set-cookie", "")
            elif where == "meta-generator":
                hay = generator
            elif where == "body":
                hay = body[:60000]
            if hay and re.search(pattern, hay, re.I):
                version = self._version_for(name, cat, headers, generator)
                self.ctx.add_fingerprint(name, cat, version)

        fps = self.ctx.fingerprints
        if fps:
            by_cat = {}
            for f in fps:
                by_cat.setdefault(f["category"], []).append(
                    f["name"] + (f" {f['version']}" if f["version"] else ""))
            for cat, names in by_cat.items():
                detail = f"{cat}: {', '.join(sorted(set(names)))}"
                log("INFO", f"  指纹 - {detail}")
                self.add("信息泄露", "INFO", f"识别到 {detail}",
                         url=self.target, confidence="信息")
            # WAF 单独提醒
            wafs = [f["name"] for f in fps if f["category"] == "WAF"]
            if wafs:
                self.add("信息泄露", "INFO",
                         f"检测到 WAF: {', '.join(sorted(set(wafs)))}（后续检测可能被拦截）",
                         url=self.target, confidence="信息")
        else:
            log("INFO", "  未匹配到已知指纹")

    @staticmethod
    def _version_for(name, category, headers, generator) -> str:
        """按来源精确取版本，避免把 CMS 的 generator 版本误套到语言/服务器上。"""
        # 语言/框架：优先从 x-powered-by 抓「名称/版本」
        xpb = headers.get("x-powered-by", "")
        if name == "ASP.NET":
            return headers.get("x-aspnet-version", "") or _match(rf'ASP\.NET[/ ]?([\d.]+)', xpb)
        if name == "PHP":
            return _match(r'PHP/([\d.]+)', xpb)
        if name in ("Express", "Node.js", "Python"):
            return _match(rf'{re.escape(name)}[/ ]([\d.]+)', xpb)
        # 服务器：从 Server 头抓
        if category == "服务器":
            return _match(rf'{re.escape(name)}[/ ]([\d.]+)', headers.get("server", ""))
        # CMS：才用 meta generator 的版本
        if category == "CMS" and generator:
            return _match(r'([\d]+\.[\d.]+)', generator)
        return ""


def _match(pattern, text):
    m = re.search(pattern, text or "", re.I)
    return m.group(1) if m else ""
