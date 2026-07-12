"""Scoring / classification for vuln-monitor.

Patterns, score(), and dashboard category labels. Keep this module free of
I/O (no DB, no HTTP, no env credentials) so unit tests stay fast and pure.
"""
import re


def _ab(acro):
    """Acronym wrapped in ASCII-letter boundaries. Unlike \\b, this still matches
    when the acronym is glued to CJK characters (Python's \\b treats CJK as \\w,
    so \\bRCE\\b misses '认证绕过RCE漏洞')."""
    return f"(?<![a-zA-Z]){acro}(?![a-zA-Z])"


# ================== RCE PATTERNS ==================
RCE_PATTERNS = [
    # naming
    _ab("RCE"), r"remote code execution", r"arbitrary (?:\w+ ){0,3}(?:code|(?<!sql )commands?) execution",
    r"(?<![a-zA-Z])command execution(?![a-zA-Z])", r"(?<![a-zA-Z])code execution(?![a-zA-Z])",  # bare exec forms
    r"execute arbitrary (?:\w+ ){0,3}(?:code|(?<!sql )commands?)", r"execution of arbitrary (?:\w+ ){0,3}(?:code|(?<!sql )commands?)",
    r"code injection", r"(?<!SQL )command injection", r"OS command injection",
    # Chinese
    r"远程代码执行", r"远程命令执行", r"代码执行漏洞", r"命令执行漏洞", r"任意代码执行", r"反序列化漏洞",
    # NOTE: 'unauthenticated'/'pre-auth'/'unauth' are auth *prerequisites*, not RCE
    # indicators — kept OUT of RCE_PATTERNS so unauth privesc/SQLi/info-disclosure
    # don't get mislabeled RCE. Real unauth RCE is still caught by the exec keywords
    # above. Deserialization primitives below carry RCE on their own merits.
    # deserialization / injection
    r"deserializ\w*",  # all forms: deserialize/deserialized/deserializes/deserializing/deserialization/deserializer
    r"object injection", r"\bunserialize\b", r"pop chain", r"gadget chain",
    _ab("SSTI"), r"server[- ]side template injection",
    _ab("SSRF") + r".*(?:\bRCE\b|code exec|chain|gadget)",
    _ab("XXE") + r".*(?:\bRCE\b|exec|chain)",
    r"SQL injection.*(?:\bRCE\b|xp_cmdshell|OS cmd|command\b|exec\b)",  # \bRCE\b: don't match 'rce' in 'Commerce'/'Premmerce'; exec\b/command\b: avoid 'execute'/'commands'
    r"prototype pollution.*(?:\bRCE\b|exec|gadget|chain)",
    _ab("JNDI"), _ab("OGNL"),
    # memory corruption
    r"memory corruption", r"stack[- ]?(based )?(buffer )?overflow", r"heap[- ]?(based )?(buffer )?overflow",
    r"use[- ]after[- ]free\b", _ab("UAF"), r"double free",
    r"type confusion", r"out[- ]of[- ]bounds? (read|write)", _ab("OOB"),
    r"integer overflow.*(?:exec|\bRCE\b|oob)",
    r"race condition.*(?:exec|\bRCE\b|kernel)",
    # file upload / traversal / file-write escalating to exec
    r"(?:unrestricted|arbitrary|unauthenticated|unauth) file upload",
    r"任意文件上传", r"文件上传漏洞",
    r"(?:path|directory) traversal.*(?:write|overwrite|exec|upload|\bRCE\b)",
    r"webshell",
    r"arbitrary file write", r"(?:create|overwrite|truncate) arbitrary files?",
    # in-the-wild / value tags
    r"exploited in the wild", r"active(ly)? exploited", r"in[- ]the[- ]wild exploit",
    r"zero[- ]?day\b", r"\b0[- ]?day\b",
    r"exploit chain", r"full chain", r"pre[- ]auth.*(?:chain|code exec|\bRCE\b)",
    # famous exploit nicknames
    r"log4shell", r"spring4shell", r"proxyshell", r"proxylogon", r"proxynotshell",
    r"bluekeep", r"eternalblue", r"shellshock", r"heartbleed",
    r"zerologon", r"printnightmare", r"hivenightmare", r"follina",
    r"citrix\s?bleed", r"ghostcat", r"dirtycow", r"dirty pipe", r"looney tunables",
    r"regresshion", r"text4shell",
]

# ================== BYPASS PATTERNS ==================
BYPASS_PATTERNS = [
    r"auth(entication|orization)?\s*bypass",
    r"bypass\s*auth(entication|orization)?",
    r"access control bypass",
    r"permission bypass",
    _ab("RBAC") + r".*bypass", r"bypass.*" + _ab("RBAC"),
    r"security (feature )?bypass",
    r"account takeover",
    r"session (hijack|fixation|steal)",
    r"token (leak|expos|disclos|forg)",
    r"JWT.*(bypass|weak|forg|leak)",
    r"credential.*(leak|expos|bypass|steal)",
    r"认证绕过", r"权限绕过", r"身份验证绕过",
]


# ================== ASSET KEYWORDS ==================
ASSET_KEYWORDS = [
    # ----- boundary / VPN / firewall / remote access -----
    "citrix","netscaler","adc","citrix gateway","xenapp","xenmobile",
    "fortinet","fortigate","fortios","fortimanager","fortiproxy","fortiweb","fortiadc","fortinac","fortiswitch","fortianalyzer","fortiportal","fortisiem","fortisoar",
    "ivanti","pulse secure","pulse connect","connect secure","ivanti epm","endpoint manager","avalanche","neurons","moveit","goanywhere","ivanti csa",
    "palo alto","globalprotect","pan-os","prisma","expedition","cortex",
    "cisco asa","cisco ftd","firepower","anyconnect","cisco ios","ios-xe","ios-xr","nx-os","ise","ucs","dna center","webex","sd-wan","cisco meraki","cucm","callmanager",
    "f5","big-ip","big-iq","nginx plus",
    "checkpoint","check point","gaia","harmony",
    "sonicwall","sma","sma 100","sma 200","tz","nsa",
    "zyxel","juniper","junos","junos space","nsm",
    "barracuda","esg","barracuda waf","barracuda backup",
    "sophos","sfos","xg firewall","sophos utm",
    "watchguard","firebox","stormshield","kemp loadmaster","a10","array networks",
    "mikrotik","routeros","pfsense","opnsense",
    "aruba","clearpass","aruba controller","arubaos","arubaos-switch",
    "hp procurve","aruba cx","d-link","tp-link","tp link","totolink","netgear","asus router","draytek","vigor","tenda","linksys","ubiquiti","unifi","edgerouter",
    "rdp","remote desktop","terminal server","rds","rdweb","rdgateway","rdp client",
    "smb","smbv1","smbv2","smbv3","cifs","netbios",
    "openssh","ssh","vnc","telnet","winrm","rpc","dcom","rras",
    "teamviewer","anydesk","rustdesk","splashtop","logmein","connectwise","screenconnect","kaseya","vsa","n-able","n-central","atera","ninjarmm","dameware","dwservice",

    # ----- Microsoft -----
    "windows","windows server","windows 10","windows 11",
    "active directory","domain controller","ad cs","ad fs","adfs","ntlm","kerberos","ldap","dns server","dhcp","spn","gmsa",
    "exchange","exchange online","outlook","owa","ecp",
    "microsoft 365","office 365","office","word","excel","powerpoint","onenote","visio","access",
    "sharepoint","teams","skype","lync","onedrive","dynamics 365","dynamics crm","dynamics ax","dynamics nav",
    "iis","asp.net","aspnet",".net","dotnet","kestrel","msmq",
    "hyper-v","hyperv","wsl","wsa",
    "azure","azure ad","entra","entra id","intune","defender","defender for endpoint","defender for office","defender for identity",
    "wsus","sccm","mecm","configuration manager","system center","scom","scvmm",
    "print spooler","spoolsv","msdtc","mshtml","jscript","vbscript",
    "visual studio","vscode","msbuild","powershell","wmi","wmic",
    "mssql","sql server","ssrs","ssis","ssas",
    "edge","internet explorer","chakra","media foundation","windows codecs","directx","directshow",
    "smartscreen","applocker","mpengine","mpclient","windows defender",

    # ----- databases -----
    "mysql","mariadb","percona",
    "postgresql","postgres","timescaledb","redshift","greenplum",
    "oracle database","oracle db","oracle weblogic","oracle ebs","e-business suite","peoplesoft","jd edwards","oracle middleware","oracle fusion","opatch","oracle tuxedo",
    "mssql","sql server","sybase","sap ase",
    "mongodb","mongo","cosmosdb",
    "redis","keydb","dragonflydb","valkey",
    "elasticsearch","opensearch","elastic","kibana","logstash","beats","fleet",
    "clickhouse","cassandra","scylladb","hbase","accumulo",
    "influxdb","questdb","victoriametrics",
    "couchdb","couchbase","ravendb","firebird","foxpro",
    "memcached","etcd","consul",
    "neo4j","arangodb","janusgraph",
    "db2","informix","teradata","vertica","snowflake","databricks",
    "splunk","splunk enterprise","splunk universal forwarder","splunk phantom",
    "h2 database","h2 console","hsqldb","derby",
    "dm8","达梦","kingbase","人大金仓","tidb","oceanbase",

    # ----- virt / container / k8s / cloud-native -----
    "vmware","vcenter","esxi","vsphere","workstation","fusion","horizon","airwatch","workspace one","nsx","vrealize","aria","tanzu",
    "proxmox","xenserver","citrix hypervisor","xcp-ng","kvm","qemu","libvirt","virtualbox","parallels",
    "docker","docker engine","docker desktop","containerd","runc","cri-o","podman","buildah","skopeo","lxc","lxd","openvz",
    "kubernetes","k8s","kube-apiserver","kubelet","kube-proxy","kubeadm","helm","rancher","openshift","ocp","eks","aks","gke","kops",
    "istio","linkerd","envoy","cilium","calico","flannel","weave",
    "argo","argocd","flux","tekton","spinnaker","crossplane","knative",
    "nomad","consul","vault","terraform","terragrunt","packer","ansible","awx","ansible tower","chef","puppet","saltstack","salt master","rundeck",
    "openstack","nova","neutron","swift","keystone","cinder",
    "harbor","quay","nexus","artifactory","jfrog",

    # ----- CI/CD / devtools / package managers -----
    "jenkins","gitlab","gitea","gogs","github enterprise","github actions","bitbucket","bitbucket server","subversion","svn","mercurial","perforce",
    "teamcity","bamboo","circleci","buildkite","drone","woodpecker","concourse","travis","azure devops","vsts","tfs","azure pipelines",
    "docker registry","distribution",
    "sonarqube","sonar","snyk","fortify","checkmarx","veracode",
    "maven","gradle","npm","yarn","pnpm","pip","pypi","composer","packagist","rubygems","bundler","nuget","cargo","go modules","stack","mix",
    "phabricator","gerrit",

    # ----- web servers / middleware / app servers / MQ -----
    "apache","apache httpd","httpd","nginx","caddy","lighttpd","h2o","openresty","tengine",
    "tomcat","jetty","undertow","resin",
    "weblogic","websphere","jboss","wildfly","glassfish","payara","jeus",
    "kestrel",
    "haproxy","traefik","kong","apisix","tyk","apigee","wso2","zuul",
    "varnish","squid",
    "rabbitmq","activemq","kafka","pulsar","nats","mosquitto","emqx","nsq","zeromq",
    "zookeeper","bookkeeper",
    "apache shiro","shiro","apache dubbo","dubbo","dubbo admin","apache superset","apache airflow","airflow","apache nifi","nifi","apache druid","druid","apache kylin","kylin","apache ofbiz","ofbiz","apache solr","solr","apache flink","flink","apache spark","spark","apache storm","apache cxf","cxf","apache camel","camel","apache poi","poi","apache fineract","apache unomi","unomi","apache skywalking","apache seatunnel","seatunnel","apache linkis","linkis","apache streampipes","apache inlong","inlong","apache rocketmq","rocketmq","apache iotdb","apache atlas",

    # ----- frameworks / runtimes -----
    "log4j","log4j2","log4net","logback","slf4j",
    "spring","spring framework","spring boot","spring cloud","spring security","spring cloud gateway","spring cloud function","spring data","spring webflow",
    "struts","apache struts","struts2",
    "fastjson","jackson","xstream","snakeyaml","dom4j","xmlbeans",
    "laravel","symfony","codeigniter","yii","cakephp","zend","thinkphp","phalcon","slim",
    "django","flask","fastapi","tornado","pyramid","aiohttp","werkzeug","jinja","bottle",
    "rails","ruby on rails","sinatra","padrino",
    "express","koa","hapi","nestjs","next.js","nuxt","gatsby","sveltekit","remix","astro","fastify",
    "asp.net core","blazor","razor",
    "gin","echo","fiber","beego",
    "actix","axum","rocket","warp",
    "node.js","nodejs","deno","bun",
    "php","php-fpm","cgi","fastcgi",

    # ----- CMS / e-commerce / forum / wiki -----
    "wordpress","wp plugin","elementor","woocommerce",
    "drupal","joomla","magento","prestashop","opencart","shopify","bigcommerce","oscommerce",
    "phpmyadmin","phpbb","vbulletin","xenforo","mybb","discuz","dedecms","ecshop","eyoucms","phpcms","seacms","jeecms","siteserver","dotnetnuke","dnn","umbraco","kentico","sitecore","episerver","optimizely","adobe experience manager","aem",
    "typo3","concrete5","silverstripe","craft cms","ghost","strapi","directus","keystone","contentful","sanity",
    "mediawiki","dokuwiki","bookstack","xwiki","confluence","notion",
    "liferay","alfresco","nuxeo","documentum","sharepoint","owncloud","nextcloud","seafile","pydio",

    # ----- mail servers / collaboration -----
    "exim","postfix","sendmail","qmail","opensmtpd","dovecot","courier","cyrus",
    "zimbra","lotus domino","ibm domino","notes",
    "roundcube","horde","squirrelmail","afterlogic","icewarp","mdaemon","hmailserver","mailenable","open-xchange",
    "slack","mattermost","rocket.chat","discord","zulip","lark","feishu","dingtalk","wecom",
    "zoom","gotomeeting","bluejeans",
    "asterisk","freeswitch","kamailio","opensips","3cx","avaya","mitel","grandstream","yealink",

    # ----- backup / storage / file transfer -----
    "veeam","commvault","veritas","netbackup","backup exec","rubrik","cohesity","arcserve","unitrends","acronis","datto",
    "truenas","freenas","synology","dsm","qnap","qts","netapp","ontap","dell emc","isilon","data domain","powerprotect","nas","san",
    "accellion","fta","kiteworks","filecloud","crushftp","serv-u","wsftp","wing ftp","filezilla server","pureftpd","vsftpd","proftpd",

    # ----- monitoring / ITSM / RMM / inventory -----
    "zabbix","nagios","nagios xi","icinga","prtg","librenms","cacti","observium","op5","whatsup gold","checkmk","pandora fms",
    "prometheus","grafana","alertmanager","thanos","cortex","loki","tempo","jaeger","zipkin",
    "elk","graylog","logrhythm","qradar","arcsight","sumologic","datadog","new relic","appdynamics","dynatrace","instana","sentry",
    "manageengine","adselfservice","adaudit","desktop central","endpoint central","servicedesk plus","servicenow","bmc remedy","helix","jira service management","opmanager","applications manager","password manager pro","exchange reporter plus","mobile device manager plus","patch manager plus","access manager plus","pam360",
    "lansweeper","solarwinds","orion","sam","wpm","dameware",
    "snipe-it","osticket","glpi","otrs","zammad","spiceworks","freshservice",

    # ----- security products -----
    "crowdstrike","sentinelone","carbon black","cylance","defender atp","mde",
    "kaspersky","symantec","norton","mcafee","trend micro","bitdefender","eset","avast","avg","comodo","sophos central","fortiedr","cortex xdr","cortex xsoar","demisto","phantom","swimlane","tines",
    "360安全","奇安信","天擎","qax edr","深信服","sangfor","绿盟","venustech","安恒",
    "nessus","qualys","rapid7","insightvm","nexpose","tenable","acunetix","appscan","burp","burp suite","netsparker","invicti","nikto","wpscan",

    # ----- PKI / identity / secrets -----
    "keycloak","okta","auth0","ping identity","pingfederate","pingaccess","onelogin","duo","centrify","beyondtrust","cyberark","thycotic","delinea","hashicorp vault","conjur",
    "freeipa","openldap","389-ds","apache directory","samba","winbind","sssd",
    "certbot","acme","step-ca","ejbca","dogtag","venafi",
    "password manager","lastpass","1password","bitwarden","vaultwarden","keepass","passbolt","psono","enpass",

    # ----- archivers / parsers / media -----
    "winrar","7-zip","7zip","peazip","unrar","unzip","tar","zstd","bzip2","xz",
    "adobe reader","acrobat","foxit","pdfium","mupdf","poppler","sumatrapdf","nitro pdf",
    "imagemagick","graphicsmagick","libjpeg","libpng","libwebp","libtiff","libheif","libvips","exiftool","exiv2","libraw",
    "ffmpeg","libav","x264","x265","gstreamer","vlc","stagefright",
    "libxml","libxml2","libxslt","expat",
    "openssl","libssl","wolfssl","mbedtls","gnutls","nss","boringssl","libssh","libssh2",
    "curl","libcurl","wget","stunnel",

    # ----- browsers / engines -----
    "chrome","chromium","v8","blink","firefox","spidermonkey","safari","webkit","gecko","edge","brave","opera","vivaldi",
    "electron","cef","webview","webview2","wasmtime",

    # ----- BMC / firmware -----
    "ipmi","idrac","ilo","xclarity","ami megarac","megarac","bmc","redfish","cimc","imm",
    "bios","uefi","tpm","intel amt","intel me","amd psp",

    # ----- ICS / OT (optional) -----
    "siemens","simatic","wincc","step 7","rockwell","studio 5000","factorytalk","schneider","modicon","ecostruxure","mitsubishi","beckhoff","twincat","codesys","moxa","opc ua","ignition",

    # ----- cloud consoles / IAM -----
    "aws","amazon web services","ec2","s3","rds","lambda","iam","cloudfront","cloudformation","ecs","fargate",
    "azure","app service","aks","arc",
    "gcp","google cloud","gke","cloud run","cloud functions","anthos",
    "aliyun","alibaba cloud","tencent cloud","huawei cloud","qcloud","cloudflare","fastly","akamai","guardicore","incapsula","imperva",

    # ----- control panels / hosting -----
    "cpanel","plesk","webmin","usermin","virtualmin","ispconfig","directadmin","vestacp","hestiacp","cyberpanel","centos web panel","cwp","宝塔","baota","bt panel","aapanel","1panel","x-ui",
    "cockpit","unraid","homeassistant","home assistant",

    # ----- Chinese vendors / high-frequency pentest targets -----
    "用友","yonyou","金蝶","kingdee","seeyon","致远","泛微","weaver","e-office","e-cology","tongda","通达","landray","蓝凌","fastadmin",
    "h3c","华三","华为","huawei","ruijie","锐捷",

    # ----- misc media/home -----
    "jellyfin","plex","emby","sonarr","radarr","qbittorrent","transmission","deluge","sabnzbd","nzbget",
]


# ================== EXCLUDE ==================
EXCLUDE_PATTERNS = [
    _ab("XSS"), r"cross[- ]site[- ]scripting",
    _ab("CSRF"), r"cross[- ]site request forgery",
    r"clickjacking", r"open redirect", r"host header injection",
    r"information disclosure(?!.*(pre-?auth|unauth|RCE|chain|exploit|credential))",
    r"authenticated admin(?!.*(chain|bypass|RCE|0[- ]?day))",
    r"local privilege escalation(?!.*(chain|RCE|kernel 0[- ]?day))",
    _ab("DoS") + r"(?!.*(unauth|pre-?auth|chain|kernel))",
    r"denial of service(?!.*(unauth|pre-?auth|chain|kernel))",
    _ab("SSRF") + r"(?!.*(RCE|code exec|chain|bypass))",
    # Linux kernel subsystem patches (not enterprise-exploitable)
    r"\b(?:staging|ocfs2|fbdev|ALSA|media|usb: gadget|i2c:|s390/|rtnetlink|bcache|tracing):",
    # Apache library-level crashes/bugs (not enterprise-exploitable RCE)
    r"Apache Thrift:",
    # Browser patches (not actionable for infra defenders; keep actively-exploited)
    r"(?:Google Chrome|Chromium)\b(?!.*(exploit|0[- ]?day|zero[- ]?day|in[- ]the[- ]wild))",
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# Vendor advisory ID patterns (fallback when no CVE found)
ADVISORY_RE = re.compile(
    r"FG-IR-\d+-\d+"           # Fortinet
    r"|cisco-sa-[\w-]+"        # Cisco
    r"|PAN-SA-\d+-\d+"         # Palo Alto
    r"|ZDI-\d+-\d+"            # ZDI
    r"|VMSA-\d+-\d+",          # VMware
    re.I,
)

# ================== FILTER ==================
# Pre-compile patterns into single combined regexes for performance.
_RCE_RE = re.compile("|".join(f"(?:{p})" for p in RCE_PATTERNS), re.I)
_BYPASS_RE = re.compile("|".join(f"(?:{p})" for p in BYPASS_PATTERNS), re.I)
_EXCLUDE_RE = re.compile("|".join(f"(?:{p})" for p in EXCLUDE_PATTERNS), re.I)
_ASSET_KW_SET = frozenset(ASSET_KEYWORDS)

# Short ASCII tokens (len<=3) use alnum word-boundaries so e.g. "ise" does not
# match inside "enterprise"/"promise", "nsa" inside "transaction", "cvs" inside
# "CVSS", "pip" inside "response", "tar" inside "start". Longer keywords and
# CJK terms keep plain substring match (product phrases like "palo alto").
_SHORT_ASSET_MAX = 3
_SHORT_ASCII_RE = re.compile(r"^[a-z0-9][a-z0-9+./_-]*$", re.I)


def _build_asset_matchers(keywords):
    short, long_kw = [], []
    for k in keywords:
        if len(k) <= _SHORT_ASSET_MAX and _SHORT_ASCII_RE.fullmatch(k):
            short.append(re.escape(k.lower()))
        else:
            long_kw.append(k.lower())
    short_re = None
    if short:
        # longest-first so "rds" is tried before "rd" if both exist
        short.sort(key=len, reverse=True)
        short_re = re.compile(
            r"(?<![a-z0-9])(?:" + "|".join(short) + r")(?![a-z0-9])",
            re.I,
        )
    return short_re, frozenset(long_kw)


_SHORT_ASSET_RE, _LONG_ASSET_KW = _build_asset_matchers(ASSET_KEYWORDS)


def asset_hit(text_lower: str) -> bool:
    """True if text (already lowercased) mentions a watched asset/product."""
    if any(k in text_lower for k in _LONG_ASSET_KW):
        return True
    if _SHORT_ASSET_RE and _SHORT_ASSET_RE.search(text_lower):
        return True
    return False


# Unambiguous RCE indicators. If any is present, the noise EXCLUDE filters (XSS/
# CSRF/SSRF/info-disclosure/DoS) are bypassed — an XSS->RCE or "RCE ... SSRF"
# chain is still RCE regardless of which term appears first or which is stronger.
_STRONG_RCE_RE = re.compile("|".join([
    _ab("RCE"), r"remote code execution",
    r"arbitrary (?:\w+ ){0,3}(?:code|commands?) execution",
    r"webshell|web shell",
    r"arbitrary file (?:write|upload)",
    _ab("JNDI"), _ab("OGNL"),
    r"execute arbitrary (?:\w+ ){0,3}(?:code|commands?)",
]), re.I)


def score(text):
    """Score text for exploitability. Returns (hit, reason, vuln_type).

    reason: detailed match info (RCE+asset/CVE, bypass+asset/CVE, asset+CVE, etc.)
    vuln_type: simplified classification (RCE / bypass / other / None)
    """
    if not _STRONG_RCE_RE.search(text) and _EXCLUDE_RE.search(text):
        return False, "excluded", None
    low = text.lower()
    rce    = bool(_RCE_RE.search(text))
    asset  = asset_hit(low)
    cve    = bool(CVE_RE.search(text))
    bypass = bool(_BYPASS_RE.search(text))
    if rce and asset and cve:
        return True, "RCE+asset+CVE", "RCE"
    if rce and asset:
        return True, "RCE+asset", "RCE"
    if rce and cve:
        return True, "RCE+CVE", "RCE"
    if rce:
        return True, "RCE", "RCE"
    if bypass and asset and cve:
        return True, "bypass+asset+CVE", "bypass"
    if bypass and cve:
        return True, "bypass+CVE", "bypass"
    if bypass and asset:
        return True, "bypass+asset", "bypass"
    if bypass:
        return True, "bypass", "bypass"
    if asset and cve:
        return True, "asset+CVE", "other"
    return False, "no hit", None


# ================== CATEGORY (dashboard filter dimension) ==================
# One coarser "category" label per record, derived from vuln_type + reason + keywords.
# Priority: escape > RCE (by vuln_type) > keyword classes
# (SQLi > privilege escalation > bypass > data leak > XSS/SSRF > DoS)
# > bypass (by vuln_type) > other. Excluded records are keyword-categorized too
# (so e.g. an excluded SSRF still lands in XSS/SSRF, not hidden in other).
# Memory-corruption (overflow/UAF/OOB) is RCE-class, never DoS. Stored in `category`.
CATEGORY_KEYWORDS = [
    ("SQLi",                 [r"sql injection", r"\bsqli\b"]),
    ("privilege escalation", [r"privilege escalation", r"\bprivesc\b", r"elevation of privilege", r"权限提升"]),
    ("bypass",               [r"auth(?:entication|orization)?\s*(?:bypass|weak|flaw)",
                              r"access control", r"improper access", r"permission\s*(?:bypass|flaw)",
                              r"\bRBAC\b", r"security (?:feature )?bypass", r"broken access",
                              r"\bIDOR\b", r"insecure direct object", r"account takeover", r"impersonation"]),
    ("data leak",            [r"arbitrary file read", r"file read", r"path traversal", r"directory traversal",
                              r"\bLFI\b", r"local file inclusion", r"information disclosure",
                              r"sensitive (?:data|information)", r"data (?:leak|exposure|disclos)",
                              r"source (?:code )?disclos", r"credential(?:s)? leak", r"任意文件读取", r"信息泄露"]),
    ("XSS/SSRF",             [r"server[- ]side request forgery", r"\bssrf\b",
                              r"\bxss\b", r"cross[- ]site scripting", r"\bcsrf\b", r"open redirect"]),
    ("DoS",                  [r"\bdos\b", r"denial of service", r"\bcrash(?:es|ed)?\b"]),
]
_MEMCORRUPT_RE = re.compile(
    r"buffer overflow|heap overflow|stack overflow|use[- ]after[- ]free|\buaf\b"
    r"|out[- ]of[- ]bounds|memory corruption|type confusion|integer overflow", re.I)
# privilege-escalation language (noun + verb forms) for the RCE->privesc guard
_PRIVESC_RE = re.compile(
    r"privilege escalation|elevation of privilege|privilege elevation|elevat\w* privileges?",
    re.I)
# strong RCE language in a TITLE — if present, don't downgrade to privesc
_TITLE_RCE_RE = re.compile(
    _ab("RCE") + r"|remote code execution|command injection|code injection"
    r"|command execution|code execution|arbitrary code",
    re.I)

# sandbox / container / VM escape (a distinct severity dimension above RCE).
# Matches bidirectionally — escape verb may appear before or after the isolation noun.
# Examples: 'Sandbox Escape', 'container escape', 'guest-to-host', 'container hardening
# bypass', 'sandbox bypass', '...job container ... and escape to the host as root...',
# 容器/沙箱/虚拟机/虚拟化逃逸.
_ESCAPE_RE = re.compile(
    # 1. explicit <thing>-escape / <thing>-breakout (hyphen or space, high precision)
    r"\b(?:container|sandbox(?:ed|ing|es)?|namespace|chroot|hypervisor|"
    r"kvm|vmware|virtualbox|hyper[- ]?v|qemu|docker|kubernetes|k8s|kata|"
    r"vm|virtual\s+machine|jail)[\s-]+(?:escape|breakout)\b"
    # 2. escape/breakout VERB governed by a motion preposition (to/from/into/out of)
    #    OR directly taking a strong isolation noun. Requiring a governing preposition
    #    (or a strong-noun object) disambiguates the isolation-boundary sense from
    #    the quoting/encoding sense: 'escape to the host' / 'break out of the
    #    container' / 'escaping the sandbox' match, but 'escape sequence in the host
    #    header' / 'escape shell args' / 'escape the SQL quoting' do not.
    r"|\b(?:escape|escapes|escaping|breakouts?|break(?:ing)?\s+out)\b\s+"
    r"(?:(?:to|from|into|out\s+of)\s+(?:the\s+|a\s+)?"
    r"(?:container|sandbox|namespace|chroot|hypervisor|host|vm|virtual\s+machine|guest)"
    r"|(?:the\s+|a\s+)?(?:container|sandbox|namespace|chroot|hypervisor|virtual\s+machine))\b"
    # 3. isolation noun → escape/breakout verb (within 80 chars, single line).
    #    Strong nouns only — host/vm/guest excluded here (too generic without a
    #    governing preposition; covered by branch 2 when led by to/from).
    r"|\b(?:container|sandbox|namespace|chroot|hypervisor|virtual\s+machine)\b"
    r"[^\n]{0,80}\b(?:escape|breakout|escapes|escaping)\b"
    # 4. canonical phrases
    r"|\bguest[- ]?to[- ]?host\b"
    r"|\bcontainer\s+hardening\s+bypass\b"
    r"|\bcontainer\s+isolation\s+(?:bypass|escape|broken)\b"
    r"|\b(?:sandbox|sandboxed|sandboxes)\s+(?:bypass|escape|breakout)\b"
    r"|\bhost\s+namespaces?\s+(?:access|gain|injection|join|breakout)\b"
    # 5. Chinese — full CJK clauses + a Latin noun glued directly to 逃逸
    #    (\b does not fire at the CJK boundary, so 'container逃逸' needs its own alt)
    r"|容器逃逸|沙箱逃逸|虚拟机?逃逸|虚拟化逃逸|hyper[- ]?v\s*逃逸"
    r"|(?:container|sandbox|hypervisor|vm|docker|kvm|qemu|virtualbox|virtual\s+machine|jail)逃逸",
    re.I)
# LPE in TITLE → NOT escape (user instruction: do not conflate with privesc).
# Defers e.g. ZDI 'Docker Desktop ... Local Privilege Escalation' back to the
# normal privesc path.
_ESCAPE_TITLE_LPE_RE = re.compile(
    r"\blocal\s+privilege\s+escalation\b|\blpe\b",
    re.I)
# LLM model jailbreak / prompt injection → NOT escape (different concept than
# sandbox/container escape; the latter crosses a process-isolation boundary).
_LLM_JAILBREAK_RE = re.compile(
    r"prompt\s+injection|chain[- ]of[- ]logic|"
    r"(?:llm|model|chatbot|ai)\s+jailbreak",
    re.I)


def classify_category(vuln_type, text, reason=None):
    """Return one dashboard category label for a record.

    Priority: escape > RCE (by vuln_type) > keyword classes
    (SQLi > privilege escalation > bypass > data leak > XSS/SSRF > DoS)
    > bypass (by vuln_type) > other. Excluded records are keyword-categorized
    too (an excluded SSRF -> XSS/SSRF). Memory-corruption is never DoS.
    A vuln scored RCE is re-routed to privilege escalation when its TITLE says so
    (without also claiming code/command execution) or when it's a local
    memory-corruption EoP — so genuine RCEs aren't downgraded.
    Sandbox/container/VM escape is checked first (more specific severity dimension
    than RCE); LPE-titled and LLM-jailbreak records are explicitly excluded.
    """
    low = (text or "").lower()
    title_low = low.split("\n", 1)[0]
    # escape wins unless the TITLE brands it something else: a plain LPE with no
    # escape token (→ privesc path) or an LLM jailbreak. Both are title-level
    # signals, so they are checked on title_low only — a body mention of "prompt
    # injection"/"jailbreak" must not suppress a real sandbox/container escape.
    title_has_lpe = bool(_ESCAPE_TITLE_LPE_RE.search(title_low))
    title_is_escape = bool(_ESCAPE_RE.search(title_low))
    if (_ESCAPE_RE.search(low)
            and not (title_has_lpe and not title_is_escape)
            and not _LLM_JAILBREAK_RE.search(title_low)):
        return "escape"
    if vuln_type == "RCE":
        title_is_privesc = bool(_PRIVESC_RE.search(title_low)) and not _TITLE_RCE_RE.search(title_low)
        if title_is_privesc or (_MEMCORRUPT_RE.search(low) and _PRIVESC_RE.search(low) and not _TITLE_RCE_RE.search(title_low)):
            return "privilege escalation"
        return "RCE"
    for cat, patterns in CATEGORY_KEYWORDS:
        if any(re.search(p, low, re.I) for p in patterns):
            if cat == "DoS" and _MEMCORRUPT_RE.search(low):
                return "other"  # overflow/UAF/OOB is RCE-class, not DoS
            return cat
    if vuln_type == "bypass":
        return "bypass"
    return "other"

