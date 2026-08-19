"""
敏感路径库（供 modules/exposure.py 使用）
Author: 火柴 | GitHub: huocai250

这里收录公开已知的敏感/配置/备份/面板等路径。检测采用「软 404 基线对比 +
可选内容签名」以降低误报。仅做存在性检测，不利用。

条目格式: (path, severity, [signature_words])
  - signature_words 非空：命中任一签名词才判定
  - signature_words 为空：依赖软 404 基线判定（返回 200 且明显不同于 404 页）
"""

# ---- 版本控制系统 ----
_VCS = [
    (".git/config", "MEDIUM", ["[core]", "repositoryformatversion"]),
    (".git/HEAD", "MEDIUM", ["ref: refs/"]),
    (".git/index", "MEDIUM", []),
    (".git/logs/HEAD", "MEDIUM", []),
    (".git/COMMIT_EDITMSG", "LOW", []),
    (".gitignore", "LOW", []),
    (".gitattributes", "LOW", []),
    (".svn/entries", "MEDIUM", []),
    (".svn/wc.db", "MEDIUM", []),
    (".hg/store", "MEDIUM", []),
    (".hgignore", "LOW", []),
    (".bzr/README", "LOW", []),
    ("CVS/Root", "LOW", []),
    ("CVS/Entries", "LOW", []),
    (".gitlab-ci.yml", "LOW", ["stages:", "script:"]),
    (".travis.yml", "LOW", ["language:", "script:"]),
    (".circleci/config.yml", "LOW", ["version:", "jobs:"]),
    (".github/workflows/main.yml", "LOW", ["on:", "jobs:"]),
    ("Jenkinsfile", "LOW", ["pipeline", "stage", "node {"]),
]

# ---- 环境/密钥/凭据 ----
_SECRETS = [
    (".env", "HIGH", ["DB_", "APP_", "SECRET", "PASSWORD", "API_KEY"]),
    (".env.local", "HIGH", ["DB_", "SECRET", "PASSWORD"]),
    (".env.dev", "HIGH", ["DB_", "SECRET"]),
    (".env.production", "HIGH", ["DB_", "SECRET"]),
    (".env.backup", "HIGH", ["DB_", "SECRET"]),
    (".env.example", "LOW", ["DB_", "APP_"]),
    ("config/secrets.yml", "HIGH", ["secret_key_base", "password"]),
    ("config/database.yml", "HIGH", ["adapter", "password", "username"]),
    ("credentials.json", "HIGH", ["private_key", "client_email", "token"]),
    ("service-account.json", "HIGH", ["private_key", "client_email"]),
    (".aws/credentials", "CRITICAL", ["aws_access_key_id", "aws_secret"]),
    (".npmrc", "MEDIUM", ["_authToken", "//registry"]),
    (".dockercfg", "MEDIUM", ["auth", "registry"]),
    (".docker/config.json", "MEDIUM", ["auths", "auth"]),
    ("id_rsa", "CRITICAL", ["PRIVATE KEY"]),
    ("id_dsa", "CRITICAL", ["PRIVATE KEY"]),
    ("server.key", "CRITICAL", ["PRIVATE KEY"]),
    ("private.pem", "CRITICAL", ["PRIVATE KEY"]),
    ("privatekey.pem", "CRITICAL", ["PRIVATE KEY"]),
    (".ssh/id_rsa", "CRITICAL", ["PRIVATE KEY"]),
    (".ssh/known_hosts", "MEDIUM", ["ssh-rsa", "ssh-ed25519"]),
    (".htpasswd", "HIGH", [":$", ":$apr1$"]),
    ("secrets.json", "HIGH", ["password", "secret", "key"]),
]

# ---- 配置文件 ----
_CONFIG = [
    ("web.config", "MEDIUM", ["<configuration>", "connectionStrings"]),
    ("app.config", "MEDIUM", ["<configuration>", "appSettings"]),
    ("application.properties", "HIGH", ["spring.", "datasource", "password"]),
    ("application.yml", "HIGH", ["spring:", "datasource", "password"]),
    ("config.php", "MEDIUM", ["<?php", "define(", "DB_"]),
    ("config.inc.php", "MEDIUM", ["<?php", "password"]),
    ("configuration.php", "MEDIUM", ["<?php", "public $"]),
    ("settings.py", "HIGH", ["SECRET_KEY", "DATABASES", "DEBUG"]),
    ("local_settings.py", "HIGH", ["SECRET_KEY", "DATABASES"]),
    ("wp-config.php", "CRITICAL", ["DB_PASSWORD", "DB_NAME"]),
    ("web.xml", "LOW", ["<web-app", "servlet"]),
    ("struts.xml", "LOW", ["<struts>", "action"]),
    ("Dockerfile", "LOW", ["FROM ", "RUN "]),
    ("docker-compose.yml", "MEDIUM", ["services:", "image:"]),
    ("nginx.conf", "MEDIUM", ["server {", "location"]),
    ("httpd.conf", "MEDIUM", ["ServerRoot", "DocumentRoot"]),
    (".htaccess", "LOW", ["RewriteEngine", "AuthType"]),
    ("crossdomain.xml", "LOW", ["cross-domain-policy", "allow-access-from"]),
    ("clientaccesspolicy.xml", "LOW", ["access-policy", "cross-domain-access"]),
    ("phpunit.xml", "LOW", ["<phpunit", "testsuite"]),
    ("composer.json", "LOW", ["require", "autoload"]),
    ("composer.lock", "LOW", ["packages", "content-hash"]),
    ("package.json", "LOW", ["dependencies", "scripts"]),
    ("yarn.lock", "LOW", ["# yarn lockfile", "resolved"]),
    ("Gemfile", "LOW", ["source ", "gem "]),
    ("Gemfile.lock", "LOW", ["GEM", "specs:"]),
    ("requirements.txt", "LOW", ["==", ">="]),
    ("pom.xml", "LOW", ["<project", "<dependency>"]),
    ("build.gradle", "LOW", ["dependencies", "repositories"]),
    ("tsconfig.json", "LOW", ["compilerOptions"]),
    ("webpack.config.js", "LOW", ["module.exports", "entry"]),
]

# ---- 备份/临时文件 ----
_BACKUP = [
    ("backup.sql", "HIGH", ["INSERT INTO", "CREATE TABLE"]),
    ("dump.sql", "HIGH", ["INSERT INTO", "CREATE TABLE"]),
    ("database.sql", "HIGH", ["INSERT INTO", "CREATE TABLE"]),
    ("db.sql", "HIGH", ["INSERT INTO", "CREATE TABLE"]),
    ("backup.zip", "MEDIUM", []),
    ("backup.tar.gz", "MEDIUM", []),
    ("backup.rar", "MEDIUM", []),
    ("www.zip", "MEDIUM", []),
    ("web.zip", "MEDIUM", []),
    ("site.tar.gz", "MEDIUM", []),
    ("wwwroot.zip", "MEDIUM", []),
    ("backup.tar", "MEDIUM", []),
    ("index.php.bak", "MEDIUM", ["<?php"]),
    ("index.php~", "MEDIUM", ["<?php"]),
    ("config.php.bak", "HIGH", ["<?php"]),
    ("wp-config.php.bak", "CRITICAL", ["DB_PASSWORD"]),
    ("wp-config.php.save", "CRITICAL", ["DB_PASSWORD"]),
    (".index.php.swp", "MEDIUM", []),
    ("index.php.orig", "MEDIUM", ["<?php"]),
    ("index.html.bak", "LOW", []),
    (".DS_Store", "LOW", ["Bud1"]),
    ("Thumbs.db", "LOW", []),
]

# ---- 日志文件 ----
_LOGS = [
    ("error.log", "MEDIUM", ["PHP", "error", "stack trace"]),
    ("errors.log", "MEDIUM", ["error", "Exception"]),
    ("access.log", "LOW", ["GET ", "HTTP/1"]),
    ("debug.log", "MEDIUM", ["DEBUG", "Notice", "Warning"]),
    ("laravel.log", "MEDIUM", ["production.ERROR", "Stack trace"]),
    ("storage/logs/laravel.log", "MEDIUM", ["production.ERROR"]),
    ("wp-content/debug.log", "MEDIUM", ["PHP Notice", "PHP Warning"]),
    ("logs/error.log", "MEDIUM", ["error"]),
    ("log/production.log", "MEDIUM", ["Started ", "Processing"]),
    ("npm-debug.log", "LOW", ["npm ERR"]),
]

# ---- 服务器信息/调试 ----
_INFO = [
    ("phpinfo.php", "MEDIUM", ["PHP Version", "phpinfo()"]),
    ("info.php", "MEDIUM", ["PHP Version", "phpinfo()"]),
    ("test.php", "LOW", ["PHP Version"]),
    ("server-status", "MEDIUM", ["Apache Server Status", "Server uptime"]),
    ("server-info", "MEDIUM", ["Apache Server Information"]),
    ("nginx_status", "LOW", ["Active connections:"]),
    ("status", "LOW", ["Active connections:", "server accepts"]),
    ("metrics", "LOW", ["# HELP", "# TYPE"]),
    ("actuator", "MEDIUM", ["_links", "self"]),
    ("actuator/health", "LOW", ["status", "UP"]),
    ("actuator/env", "HIGH", ["propertySources", "activeProfiles"]),
    ("actuator/heapdump", "CRITICAL", []),
    ("actuator/mappings", "MEDIUM", ["dispatcherServlet"]),
    ("actuator/beans", "MEDIUM", ["beans"]),
    ("debug/default/view", "MEDIUM", ["Yii", "debug"]),
    ("_profiler/", "MEDIUM", ["Symfony Profiler"]),
]

# ---- 管理/登录面板 ----
_PANELS = [
    ("admin/", "LOW", ["login", "admin", "password"]),
    ("administrator/", "LOW", ["login", "admin"]),
    ("login/", "LOW", ["login", "password", "username"]),
    ("admin/login", "LOW", ["login", "password"]),
    ("admin.php", "LOW", ["login", "admin"]),
    ("wp-admin/", "LOW", ["wordpress", "wp-login"]),
    ("wp-login.php", "LOW", ["user_login", "wordpress"]),
    ("phpmyadmin/", "MEDIUM", ["phpMyAdmin"]),
    ("pma/", "MEDIUM", ["phpMyAdmin"]),
    ("adminer.php", "MEDIUM", ["Adminer"]),
    ("manager/html", "HIGH", ["Tomcat", "Unauthorized"]),
    ("jmx-console/", "HIGH", ["JBoss", "JMX"]),
    ("console/", "MEDIUM", ["console", "login"]),
    ("solr/", "HIGH", ["Solr Admin", "solr"]),
    ("jenkins/", "HIGH", ["Jenkins", "Dashboard"]),
    ("grafana/login", "MEDIUM", ["grafana"]),
    ("druid/index.html", "MEDIUM", ["Druid Stat"]),
    ("swagger-ui.html", "LOW", ["swagger", "Swagger UI"]),
    ("api-docs", "LOW", ["swagger", "openapi"]),
    ("graphql", "LOW", ["graphql", "__schema", "query"]),
    ("rockmongo/", "MEDIUM", ["RockMongo"]),
    ("mongo-express/", "MEDIUM", ["mongo-express"]),
]

# ---- 框架/CMS 特定 ----
_FRAMEWORK = [
    ("wp-json/wp/v2/users", "MEDIUM", ["slug", "name"]),
    ("xmlrpc.php", "LOW", ["XML-RPC", "methodCall"]),
    ("readme.html", "LOW", ["WordPress"]),
    ("wp-content/uploads/", "LOW", ["Index of"]),
    ("configuration.php~", "HIGH", ["public $", "password"]),
    ("administrator/manifests/files/joomla.xml", "LOW", ["<version>", "Joomla"]),
    ("sites/default/settings.php", "HIGH", ["$databases", "password"]),
    ("CHANGELOG.txt", "LOW", ["Drupal", "SECURITY"]),
    ("core/CHANGELOG.txt", "LOW", ["Drupal"]),
    ("telescope/requests", "MEDIUM", ["Telescope"]),
    ("_ignition/health-check", "HIGH", ["ignition", "can_execute_commands"]),
    ("index.php?s=captcha", "MEDIUM", ["think\\", "ThinkPHP"]),
    ("actuator/gateway/routes", "HIGH", ["predicate", "route_id"]),
]

# ---- 云/容器/K8s ----
_CLOUD = [
    (".well-known/security.txt", "INFO", ["Contact:", "Policy:"]),
    (".well-known/openid-configuration", "INFO", ["issuer", "authorization_endpoint"]),
    ("metadata", "MEDIUM", ["instance-id", "ami-id"]),
    (".kube/config", "CRITICAL", ["apiVersion", "clusters", "client-key"]),
    ("kubernetes/admin.conf", "CRITICAL", ["apiVersion", "clusters"]),
]

# ---- 更多管理/面板/接口路径（精选，真实常见）----
_MORE_PANELS = [
    ("cpanel", "LOW", ["cPanel", "login"]),
    ("webmail", "LOW", ["webmail", "login"]),
    ("plesk", "LOW", ["Plesk", "login"]),
    ("directadmin", "LOW", ["DirectAdmin"]),
    ("kibana/app/kibana", "MEDIUM", ["kibana", "kbn-"]),
    ("_plugin/head/", "HIGH", ["elasticsearch", "cluster"]),
    ("wp-admin/admin-ajax.php", "LOW", ["0", "admin-ajax"]),
    ("wp-cron.php", "LOW", []),
    ("user/login", "LOW", ["login", "Drupal", "username"]),
    ("admin/index.php", "LOW", ["login", "admin"]),
    ("manage/account/login", "LOW", ["login"]),
    ("portal/", "LOW", ["portal", "login"]),
    ("dashboard/", "LOW", ["dashboard", "login"]),
    ("actuator/loggers", "MEDIUM", ["configuredLevel"]),
    ("actuator/threaddump", "MEDIUM", ["threads", "threadName"]),
    ("actuator/httptrace", "MEDIUM", ["traces", "timestamp"]),
    ("actuator/scheduledtasks", "MEDIUM", ["cron", "fixedDelay"]),
    ("api/v1/", "INFO", ["\"data\"", "\"version\"", "\"api\""]),
    ("api/v2/", "INFO", ["\"data\"", "\"version\""]),
    ("rest/", "INFO", ["\"data\"", "rest"]),
    ("jolokia/", "HIGH", ["\"agent\"", "jolokia", "\"request\""]),
    ("jolokia/list", "HIGH", ["\"domain\"", "jolokia"]),
    ("hystrix.stream", "MEDIUM", ["data:", "hystrix"]),
    ("__clockwork/latest", "MEDIUM", ["clockwork"]),
    ("debug/", "MEDIUM", ["debug", "Whoops"]),
    ("trace.axd", "MEDIUM", ["Application Trace", "trace.axd"]),
    ("elmah.axd", "HIGH", ["Error Log for", "ELMAH"]),
    ("glpi/", "LOW", ["GLPI", "login"]),
    ("zabbix/", "LOW", ["Zabbix", "login"]),
    ("nagios/", "LOW", ["Nagios", "login"]),
    ("owa/", "LOW", ["Outlook", "owa"]),
    ("ecp/", "LOW", ["Exchange", "ecp"]),
    ("vpn/", "LOW", ["VPN", "login"]),
    ("remote/login", "LOW", ["login", "Fortinet", "FortiGate"]),
    ("citrix/", "LOW", ["Citrix", "login"]),
    ("api/jsonws/invoke", "MEDIUM", ["Liferay", "jsonws"]),
]

# ---- 更多配置/源码/密钥文件（精选）----
_MORE_CONFIG = [
    ("config.yml", "MEDIUM", ["password", "database", "secret"]),
    ("config.yaml", "MEDIUM", ["password", "database", "secret"]),
    ("config.json", "MEDIUM", ["password", "apiKey", "secret"]),
    ("secrets.yaml", "HIGH", ["password", "token", "key"]),
    ("parameters.yml", "HIGH", ["database_password", "secret"]),
    ("app/etc/env.php", "HIGH", ["'key'", "'password'", "Magento"]),
    ("app/etc/local.xml", "HIGH", ["<password>", "<username>"]),
    ("WEB-INF/web.xml", "MEDIUM", ["<web-app", "servlet"]),
    ("WEB-INF/classes/application.properties", "HIGH", ["spring.", "password"]),
    ("META-INF/MANIFEST.MF", "LOW", ["Manifest-Version", "Implementation"]),
    ("appsettings.json", "HIGH", ["ConnectionStrings", "Password"]),
    ("appsettings.Development.json", "HIGH", ["ConnectionStrings"]),
    ("firebase.json", "LOW", ["hosting", "firestore"]),
    (".firebaserc", "LOW", ["projects", "default"]),
    ("terraform.tfstate", "CRITICAL", ["\"resources\"", "terraform_version"]),
    (".terraform/terraform.tfstate", "CRITICAL", ["\"resources\""]),
    ("ansible/hosts", "MEDIUM", ["[all]", "ansible_"]),
    ("inventory", "LOW", ["[all]", "ansible_host"]),
    ("vagrantfile", "LOW", ["Vagrant.configure", "config.vm"]),
    ("procfile", "LOW", ["web:", "worker:"]),
    ("makefile", "LOW", [".PHONY", "$(", "\ttarget"]),
    (".editorconfig", "LOW", ["root =", "[*]"]),
    ("robots.txt", "INFO", ["User-agent", "Disallow"]),
    ("humans.txt", "INFO", ["/* TEAM", "/* SITE"]),
    ("ecosystem.config.js", "LOW", ["apps", "pm2"]),
    ("nuxt.config.js", "LOW", ["export default", "modules"]),
    ("next.config.js", "LOW", ["module.exports", "nextConfig"]),
    ("vue.config.js", "LOW", ["module.exports", "devServer"]),
    ("angular.json", "LOW", ["projects", "architect"]),
    (".babelrc", "LOW", ["presets", "plugins"]),
    ("gruntfile.js", "LOW", ["grunt.init", "registerTask"]),
    ("gulpfile.js", "LOW", ["gulp.task", "require('gulp')"]),
]

# ---- 备份文件模糊测试（base × 扩展名；真实常用技术）----
_BACKUP_BASES = [
    "index.php", "index.html", "index.jsp", "index.asp", "config.php",
    "wp-config.php", "configuration.php", "settings.php", "database.php",
    "db.php", "conn.php", "connect.php", "admin.php", "login.php",
    "web.config", "app.config", "application.properties", "config.inc.php",
    "users", "user", "admin", "backup", "database", "db", "data", "dump",
    "site", "www", "web", "app", "sql", "test", "main", "home",
]
_BACKUP_EXTS = [".bak", ".old", ".save", ".swp", "~", ".orig", ".tmp",
                ".1", ".zip", ".tar.gz", ".rar", ".txt", ".inc", ".copy", ".back"]
# 有些 base 已经带扩展名，追加后缀；纯名字的 base 追加压缩类后缀
_BACKUP_GEN = []
for _b in _BACKUP_BASES:
    for _e in _BACKUP_EXTS:
        if "." in _b and _e in (".zip", ".tar.gz", ".rar"):
            continue  # index.php.zip 少见，跳过部分组合
        _BACKUP_GEN.append((_b + _e, "MEDIUM", []))


def _dedup(entries):
    seen, out = set(), []
    for path, sev, sig in entries:
        p = path.lstrip("/")
        if p in seen:
            continue
        seen.add(p)
        out.append((p, sev, sig))
    return out


EXPOSURES = _dedup(
    _VCS + _SECRETS + _CONFIG + _MORE_CONFIG + _BACKUP + _BACKUP_GEN
    + _LOGS + _INFO + _PANELS + _MORE_PANELS + _FRAMEWORK + _CLOUD
)
