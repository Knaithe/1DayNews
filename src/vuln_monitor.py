#!/usr/bin/env python3
"""
0day/1day RCE vulnerability intelligence aggregator.

Flow:
    RSS feeds + GitHub CVE repo search
      -> dedup by CVE / content hash
      -> keyword score (RCE pattern + asset/CVE hit, with exclude list)
      -> Telegram push

Run:
    pip install -r requirements.txt
    export TG_BOT_TOKEN=xxx TG_CHAT_ID=xxx
    python vuln_monitor.py

First run: leave TG_* unset to "dry run" and let the cache warm up, so you
don't get spammed by historical items on the real run.
"""
import os
import re
import sys
import json
import time
import hashlib
import logging
import platform
import sqlite3
import argparse
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests


# ================== CONFIG ==================
def _user_config_path() -> Path:
    """XDG-compliant per-user config path. Cross-platform.

    Linux / macOS: $XDG_CONFIG_HOME/vuln-monitor/config.json  (default ~/.config/...)
    Windows:       %APPDATA%\\vuln-monitor\\config.json
    """
    if platform.system() == "Windows":
        base = os.getenv("APPDATA") or str(Path.home())
    else:
        base = os.getenv("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "vuln-monitor" / "config.json"


USER_CONFIG_FILE = _user_config_path()


def _load_user_config() -> dict:
    """Load persisted local config. Returns {} if missing or unreadable."""
    if not USER_CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(USER_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"WARN: failed to parse {USER_CONFIG_FILE}: {e}", file=sys.stderr)
        return {}


# Resolution order for credentials:
#   1. environment variable   (CI / systemd / one-off override)
#   2. user config file       (persisted via `scripts/configure.py`)
#   3. empty string           (TG_* empty -> dry mode, no push)
_user_cfg = _load_user_config()
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or _user_cfg.get("tg_bot_token", "")
TG_CHAT_ID   = os.getenv("TG_CHAT_ID")   or _user_cfg.get("tg_chat_id", "")
GH_TOKEN     = os.getenv("GH_TOKEN")     or _user_cfg.get("gh_token", "")
PROXY        = os.getenv("HTTPS_PROXY")  or _user_cfg.get("https_proxy", "")

SCRIPT_DIR     = Path(__file__).resolve().parent
# Runtime state (cache / lock / alert-state / log) lives in DATA_DIR.
# Resolution order:
#   1. $VULN_DATA_DIR env var (systemd / deploy.sh set this explicitly)
#   2. SCRIPT_DIR.parent if SCRIPT_DIR is named "src" (repo layout: src/vuln_monitor.py)
#   3. SCRIPT_DIR (script sits at data root)
if os.getenv("VULN_DATA_DIR"):
    DATA_DIR = Path(os.getenv("VULN_DATA_DIR")).resolve()
elif SCRIPT_DIR.name == "src":
    DATA_DIR = SCRIPT_DIR.parent
else:
    DATA_DIR = SCRIPT_DIR
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_FILE        = DATA_DIR / "vuln_cache.db"
_JSON_LEGACY   = DATA_DIR / "vuln_cache.json"   # migration source
LOCK_FILE      = DATA_DIR / "vuln_monitor.lock"
ALERT_STATE    = DATA_DIR / "vuln_alert_state.json"
LOG_FILE       = DATA_DIR / "vuln_monitor.log"
CACHE_TTL_DAYS = 60
ITEM_PER_FEED  = 50
PUSH_SLEEP_SEC = 1.5
REQUEST_TIMEOUT = 20
LOG_MAX_BYTES  = 5 * 1024 * 1024
LOG_BACKUPS    = 5
ALERT_COOLDOWN_SEC = 3600

RSS_FEEDS = [
    # ---- vendor PSIRT ----
    # Citrix, F5, Assetnote intentionally omitted: no working RSS as of 2026.
    #   Citrix — Salesforce SPA (covered by watchTowr + KEV JSON + Sploitus below).
    #   F5     — my.f5.com SPA (covered by Sploitus below).
    #   Assetnote — dropped RSS after Searchlight acquisition.
    ("Fortinet",    "https://www.fortiguard.com/rss/ir.xml"),
    ("PaloAlto",    "https://security.paloaltonetworks.com/rss.xml"),
    ("Cisco",       "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    ("MSRC",        "https://api.msrc.microsoft.com/update-guide/rss"),
    ("VMware",      "https://blogs.vmware.com/security/feed"),
    # ---- Sploitus keyword feeds (fill PSIRT gaps with exploit/PoC signal) ----
    ("Sploitus_Citrix",   "https://sploitus.com/rss?query=citrix"),
    ("Sploitus_Ivanti",   "https://sploitus.com/rss?query=ivanti"),
    ("Sploitus_F5",       "https://sploitus.com/rss?query=f5+big-ip"),
    # ---- research teams ----
    ("watchTowr",   "https://labs.watchtowr.com/rss/"),
    ("ZDI",         "https://www.zerodayinitiative.com/rss/published/"),
    ("ProjectDisc", "https://blog.projectdiscovery.io/rss/"),
    ("Horizon3",    "https://www.horizon3.ai/feed/"),
    ("Rapid7",      "https://www.rapid7.com/blog/rss/"),
    ("GreyNoise",   "https://www.greynoise.io/blog/rss.xml"),
]

# CISA KEV uses a JSON endpoint (1500+ entries with structured fields, not RSS).
KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ================== RCE PATTERNS ==================
RCE_PATTERNS = [
    # naming
    r"\bRCE\b", r"remote code execution", r"arbitrary (code|command) execution",
    r"code injection", r"command injection", r"OS command injection",
    # auth prerequisite
    r"unauthenticated", r"pre[- ]?auth(entication)?", r"\bunauth\b",
    r"no authentication (required|needed)", r"anonymous\s+(access|rce|exec)",
    # deserialization / injection
    r"deserializ(ation|ing)", r"insecure deserialization", r"unsafe deserialization",
    r"\bSSTI\b", r"server[- ]side template injection",
    r"\bSSRF\b.*(RCE|code exec|chain|gadget)",
    r"\bXXE\b.*(RCE|exec|chain)",
    r"SQL injection.*(RCE|xp_cmdshell|OS cmd|command|exec)",
    r"prototype pollution.*(RCE|exec|gadget|chain)",
    r"\bJNDI\b", r"\bOGNL\b",
    # memory corruption
    r"memory corruption", r"stack[- ]?(buffer )?overflow", r"heap[- ]?overflow",
    r"use[- ]after[- ]free\b", r"\bUAF\b", r"double free",
    r"type confusion", r"out[- ]of[- ]bounds? (read|write)", r"\bOOB\b",
    r"integer overflow.*(exec|RCE|oob)",
    r"race condition.*(exec|RCE|kernel)",
    # file upload / traversal escalating to exec
    r"(unrestricted|arbitrary) file upload.*(exec|shell|webshell|RCE)",
    r"(path|directory) traversal.*(write|overwrite|exec|upload|RCE)",
    r"webshell", r"arbitrary file write.*(exec|RCE|service)",
    # in-the-wild / value tags
    r"exploited in the wild", r"active(ly)? exploited", r"in[- ]the[- ]wild exploit",
    r"zero[- ]?day\b", r"\b0[- ]?day\b",
    r"exploit chain", r"full chain", r"pre[- ]auth.*(chain|code exec|RCE)",
    # famous exploit nicknames
    r"log4shell", r"spring4shell", r"proxyshell", r"proxylogon", r"proxynotshell",
    r"bluekeep", r"eternalblue", r"shellshock", r"heartbleed",
    r"zerologon", r"printnightmare", r"hivenightmare", r"follina",
    r"citrix\s?bleed", r"ghostcat", r"dirtycow", r"dirty pipe", r"looney tunables",
    r"regresshion", r"text4shell",
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
    "hp procurve","aruba cx","d-link","tp-link","tp link","netgear","asus router","draytek","vigor","tenda","linksys","ubiquiti","unifi","edgerouter",
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
    "jenkins","gitlab","gitea","gogs","github enterprise","github actions","bitbucket","bitbucket server","subversion","svn","mercurial","perforce","cvs",
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
    r"\bXSS\b", r"cross[- ]site[- ]scripting",
    r"\bCSRF\b", r"cross[- ]site request forgery",
    r"clickjacking", r"open redirect", r"host header injection",
    r"information disclosure(?!.*(pre-?auth|unauth|RCE|chain|exploit|credential))",
    r"authenticated admin(?!.*(chain|bypass|RCE|0[- ]?day))",
    r"local privilege escalation(?!.*(chain|RCE|kernel 0[- ]?day))",
    r"\bDoS\b(?!.*(unauth|pre-?auth|chain|kernel))",
    r"denial of service(?!.*(unauth|pre-?auth|chain|kernel))",
    r"\bSSRF\b(?!.*(RCE|code exec|chain|bypass))",
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

# Sources whose advisories are high-value even when DB fields are incomplete.
HIGH_PRIORITY_SOURCES = frozenset({
    "Fortinet", "PaloAlto", "Cisco", "CISA_KEV", "ZDI",
    "watchTowr", "MSRC", "Horizon3", "ProjectDisc",
})
# Reasons that indicate a genuinely interesting finding.
STRONG_REASONS = frozenset({"RCE+asset/CVE", "asset+CVE", "RCE+exploit"})

# Fallback advisory page per vendor (used when we know the source but have no
# item-level URL).
VENDOR_URL_FALLBACK = {
    "Fortinet":     "https://www.fortiguard.com/psirt",
    "PaloAlto":     "https://security.paloaltonetworks.com",
    "Cisco":        "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    "CISA_KEV":     "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "MSRC":         "https://msrc.microsoft.com/update-guide",
    "ZDI":          "https://www.zerodayinitiative.com/advisories/published/",
    "watchTowr":    "https://labs.watchtowr.com",
    "Horizon3":     "https://www.horizon3.ai/attack-research/",
    "ProjectDisc":  "https://blog.projectdiscovery.io",
    "Rapid7":       "https://www.rapid7.com/blog/",
    "VMware":       "https://blogs.vmware.com/security/",
    "GreyNoise":    "https://www.greynoise.io/blog",
    "GitHub":       "https://github.com",
}


# ================== LOG / HTTP ==================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("vuln")

SESS = requests.Session()
SESS.headers["User-Agent"] = "vuln-intel/1.0"
if PROXY:
    SESS.proxies = {"http": PROXY, "https": PROXY}


# ================== LOCK ==================
class SingletonLock:
    """Prevent overlapping runs. fcntl on POSIX, msvcrt on Windows."""

    def __init__(self, path):
        self.path = path
        self.fh = None

    def __enter__(self):
        self.fh = open(self.path, "a+b")
        self.fh.seek(0, 2)
        if self.fh.tell() == 0:
            self.fh.write(b"0")
            self.fh.flush()
        self.fh.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as ex:
            self.fh.close()
            self.fh = None
            raise RuntimeError(f"another instance is running ({self.path}): {ex}")
        return self

    def __exit__(self, *a):
        if self.fh:
            try:
                if sys.platform != "win32":
                    import fcntl
                    fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self.fh.close()
            except Exception:
                pass


# ================== DATABASE ==================
def _get_conn():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulns (
            key        TEXT PRIMARY KEY,
            cve_id     TEXT,
            source     TEXT,
            title      TEXT NOT NULL,
            link       TEXT,
            summary    TEXT,
            reason     TEXT,
            pushed     INTEGER DEFAULT 0,
            created_at REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_id     ON vulns(cve_id)     WHERE cve_id IS NOT NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source     ON vulns(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON vulns(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pushed     ON vulns(pushed)")
    conn.commit()

def migrate_json_cache(conn):
    """One-time migration from vuln_cache.json → SQLite."""
    if not _JSON_LEGACY.exists():
        return
    if conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0] > 0:
        return
    try:
        old = json.loads(_JSON_LEGACY.read_text(encoding="utf-8"))
    except Exception:
        return
    for key, val in old.items():
        cve_id = key.split(":", 1)[1] if key.startswith("cve:") else None
        conn.execute(
            "INSERT OR IGNORE INTO vulns (key,cve_id,title,reason,pushed,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (key, cve_id, val.get("title", "")[:300], val.get("reason", ""),
             1 if val.get("pushed") else 0, val.get("ts", 0)),
        )
    conn.commit()
    _JSON_LEGACY.rename(_JSON_LEGACY.with_suffix(".json.migrated"))
    log.info(f"migrated {len(old)} entries from JSON to SQLite")

def db_cleanup(conn):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=CACHE_TTL_DAYS)).timestamp()
    conn.execute("DELETE FROM vulns WHERE created_at < ?", (cutoff,))
    conn.commit()

def _backfill_row(conn, key, it):
    """UPDATE a record's NULL fields with fresh data from a source item."""
    tag = _extract_id(it["text"], it["link"])
    conn.execute(
        "UPDATE vulns SET cve_id=COALESCE(cve_id,?), source=COALESCE(source,?), "
        "title=COALESCE(title,?), link=COALESCE(link,?), summary=COALESCE(summary,?) "
        "WHERE key=?",
        (tag if tag != "N/A" else None, it["source"],
         it["title"][:300], it["link"], it["summary"][:500], key),
    )

def _infer_source_from_title(title):
    """Best-effort vendor inference from title keywords."""
    low = (title or "").lower()
    for kw, src in (
        ("[kev]", "CISA_KEV"),
        ("zdi-", "ZDI"),
        ("fortiweb", "Fortinet"), ("fortigate", "Fortinet"), ("fortios", "Fortinet"),
        ("fortimanager", "Fortinet"), ("fortianalyzer", "Fortinet"), ("forticlient", "Fortinet"),
        ("fortiproxy", "Fortinet"), ("fortisandbox", "Fortinet"), ("fortisiem", "Fortinet"),
        ("fortisoar", "Fortinet"), ("fortiswitch", "Fortinet"), ("fortiadc", "Fortinet"),
        ("fortinac", "Fortinet"), ("fortiportal", "Fortinet"),
        ("pan-os", "PaloAlto"), ("globalprotect", "PaloAlto"), ("cortex xdr", "PaloAlto"),
        ("palo alto", "PaloAlto"), ("prisma access", "PaloAlto"),
        ("cisco", "Cisco"), ("ios-xe", "Cisco"), ("ios-xr", "Cisco"),
        ("webex", "Cisco"), ("anyconnect", "Cisco"), ("firepower", "Cisco"),
        ("vmware", "VMware"), ("vcenter", "VMware"), ("esxi", "VMware"),
    ):
        if kw in low:
            return src
    return None

def _enrich_record(cve_id, source, title, link):
    """Heuristic enrichment for incomplete records.

    Returns (cve_id, source, link) with NULLs filled where possible.
    """
    # --- infer source from advisory ID pattern ---
    if not source and cve_id:
        for pat, src in (
            (r"FG-IR-", "Fortinet"), (r"ZDI-", "ZDI"), (r"cisco-sa-", "Cisco"),
            (r"PAN-SA-", "PaloAlto"), (r"VMSA-", "VMware"),
        ):
            if re.match(pat, cve_id, re.I):
                source = src
                break
    # --- infer source from title keywords ---
    if not source:
        source = _infer_source_from_title(title)
    # --- construct link from advisory ID ---
    if not link and cve_id:
        if re.match(r"CVE-\d{4}-\d+", cve_id, re.I):
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        elif re.match(r"FG-IR-\d+-\d+", cve_id, re.I):
            link = f"https://fortiguard.fortinet.com/psirt/{cve_id}"
        elif re.match(r"ZDI-\d+-\d+", cve_id, re.I):
            link = f"https://www.zerodayinitiative.com/advisories/{cve_id}/"
        elif re.match(r"cisco-sa-", cve_id, re.I):
            link = f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{cve_id}"
        elif re.match(r"PAN-SA-", cve_id, re.I):
            link = f"https://security.paloaltonetworks.com/{cve_id}"
    # --- fallback: vendor advisory listing page ---
    if not link and source and source in VENDOR_URL_FALLBACK:
        link = VENDOR_URL_FALLBACK[source]
    return cve_id, source, link

def _auto_enrich():
    """Find incomplete strong-reason records and persist heuristic enrichment.

    Returns number of records updated.
    """
    conn = _get_conn()
    init_db(conn)
    placeholders = ",".join("?" for _ in STRONG_REASONS)
    candidates = conn.execute(
        f"SELECT key, cve_id, source, title, link FROM vulns "
        f"WHERE (link IS NULL OR link = '') AND reason IN ({placeholders})",
        tuple(STRONG_REASONS),
    ).fetchall()
    updated = 0
    for key, cve_id, source, title, link in candidates:
        new_cve, new_src, new_link = _enrich_record(cve_id, source, title, link)
        if new_link != link or new_src != source or new_cve != cve_id:
            conn.execute(
                "UPDATE vulns SET cve_id=COALESCE(?,cve_id), source=COALESCE(?,source), "
                "link=COALESCE(?,link) WHERE key=?",
                (new_cve, new_src, new_link, key),
            )
            updated += 1
    conn.commit()
    conn.close()
    return updated

def item_key(title, link, text):
    cves = sorted(set(c.upper() for c in CVE_RE.findall(text)))
    if cves:
        return "cve:" + cves[0]
    return "h:" + hashlib.sha1((title + "|" + (link or "")).encode("utf-8")).hexdigest()[:16]


# ================== FILTER ==================
def any_match(text, patterns):
    return any(re.search(p, text, re.I) for p in patterns)

def any_contains(text, kws):
    low = text.lower()
    return any(k in low for k in kws)

def score(text):
    if any_match(text, EXCLUDE_PATTERNS):
        return False, "excluded"
    rce   = any_match(text, RCE_PATTERNS)
    asset = any_contains(text, ASSET_KEYWORDS)
    cve   = bool(CVE_RE.search(text))
    if rce and (asset or cve):
        return True, "RCE+asset/CVE"
    if asset and cve:
        return True, "asset+CVE"
    if rce and "exploit" in text.lower():
        return True, "RCE+exploit"
    return False, "no hit"


# ================== SOURCES ==================
def fetch_rss(name, url):
    """Fetch with our own timeout (feedparser.parse(url) has no timeout control)."""
    out = []
    try:
        r = SESS.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if r.status_code != 200:
            log.warning(f"RSS {name} HTTP {r.status_code}")
            return out
        d = feedparser.parse(r.content)
        if getattr(d, "bozo", False) and not d.entries:
            log.warning(f"RSS {name} parse error: {getattr(d, 'bozo_exception', '')}")
            return out
        for e in d.entries[:ITEM_PER_FEED]:
            title   = (e.get("title") or "").strip()
            link    = (e.get("link") or "").strip()
            summary = re.sub(r"<[^>]+>", " ", e.get("summary", "") or "").strip()
            out.append({
                "source": name,
                "title": title,
                "link": link,
                "summary": summary[:500],
                "text": f"{title}\n{summary}",
            })
    except Exception as ex:
        log.warning(f"RSS {name} err: {ex}")
    return out

def fetch_kev_json():
    """CISA KEV: gold-standard in-the-wild exploited list. JSON with 1500+ entries."""
    out = []
    try:
        r = SESS.get(KEV_JSON_URL, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"KEV HTTP {r.status_code}")
            return out
        data = r.json()
        for v in data.get("vulnerabilities", []):
            cve = v.get("cveID", "")
            vendor = v.get("vendorProject", "")
            product = v.get("product", "")
            name = v.get("vulnerabilityName", "")
            short = v.get("shortDescription", "")
            ransomware = v.get("knownRansomwareCampaignUse", "")
            due = v.get("dueDate", "")
            title = f"[KEV] {cve} {vendor} {product}: {name}"
            summary = f"{short} (due {due}, ransomware={ransomware})"
            out.append({
                "source": "CISA_KEV",
                "title": title[:300],
                "link": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "summary": summary[:500],
                "text": f"{title}\n{summary}",
            })
    except Exception as ex:
        log.warning(f"KEV err: {ex}")
    return out


def fetch_github_cve():
    out = []
    year = datetime.now().year
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    for q in (f"CVE-{year}-", f"CVE-{year - 1}-"):
        try:
            r = SESS.get(
                "https://api.github.com/search/repositories",
                params={"q": f"{q} in:name", "sort": "updated", "order": "desc", "per_page": 30},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                log.warning(f"GitHub {q} status {r.status_code}: {r.text[:150]}")
                continue
            for repo in r.json().get("items", []):
                name = repo["full_name"]
                desc = repo.get("description") or ""
                out.append({
                    "source": "GitHub",
                    "title": name,
                    "link": repo["html_url"],
                    "summary": desc[:500],
                    "text": f"{name}\n{desc}",
                })
        except Exception as ex:
            log.warning(f"GitHub {q} err: {ex}")
        time.sleep(2)
    return out


# ================== PUSH ==================
def tg_escape(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _extract_id(text, link):
    """Extract CVE or vendor advisory ID from text+link."""
    cves = sorted(set(c.upper() for c in CVE_RE.findall(text)))
    if cves:
        return " ".join(cves)
    # fallback: vendor advisory ID from text or link
    for src in (text, link or ""):
        m = ADVISORY_RE.search(src)
        if m:
            return m.group()
    return "N/A"

def format_msg(it, reason):
    tag = _extract_id(it["text"], it["link"])
    return (
        f"<b>[{tg_escape(it['source'])}]</b> <code>{tg_escape(tag)}</code>\n"
        f"<b>{tg_escape(it['title'][:220])}</b>\n"
        f"{tg_escape(it['link'])}\n"
        f"{tg_escape(it['summary'][:400])}\n"
        f"<i>match: {tg_escape(reason)}</i>"
    )[:4000]

def send_telegram(msg):
    if not (TG_BOT_TOKEN and TG_CHAT_ID):
        log.info(f"[DRY] {msg[:500]}")
        return True
    try:
        r = SESS.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={
                "chat_id": TG_CHAT_ID,
                "text": msg,
                "parse_mode": "HTML",
                "disable_web_page_preview": False,
            },
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200:
            log.warning(f"TG push {r.status_code}: {r.text[:200]}")
            return False
        return True
    except Exception as ex:
        log.warning(f"TG err: {ex}")
        return False


def send_failure_alert(msg):
    """Rate-limited error notification so silent cron breakage is noticed."""
    now = time.time()
    state = {}
    if ALERT_STATE.exists():
        try:
            state = json.loads(ALERT_STATE.read_text(encoding="utf-8"))
        except Exception:
            pass
    if now - state.get("last_alert_ts", 0) < ALERT_COOLDOWN_SEC:
        log.warning(f"alert suppressed (cooldown): {msg[:150]}")
        return
    if not (TG_BOT_TOKEN and TG_CHAT_ID):
        log.error(f"[ALERT-DRY] {msg[:500]}")
    else:
        try:
            SESS.post(
                f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": TG_CHAT_ID,
                    "text": f"vuln-monitor error\n\n{msg[:3800]}",
                    "disable_web_page_preview": True,
                },
                timeout=REQUEST_TIMEOUT,
            )
        except Exception as ex:
            log.error(f"alert push failed: {ex}")
    state["last_alert_ts"] = now
    try:
        tmp = ALERT_STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, ALERT_STATE)
    except Exception as ex:
        log.warning(f"alert state save failed: {ex}")


# ================== MAIN ==================
def _run():
    conn = _get_conn()
    init_db(conn)
    migrate_json_cache(conn)
    now = datetime.now(timezone.utc).timestamp()

    items = []
    for name, url in RSS_FEEDS:
        items.extend(fetch_rss(name, url))
    items.extend(fetch_kev_json())
    items.extend(fetch_github_cve())
    log.info(f"collected {len(items)} items")

    seen_this_run = set()
    pushed = 0
    skipped_seen = 0
    skipped_filter = 0
    backfilled = 0

    for it in items:
        key = item_key(it["title"], it["link"], it["text"])
        if key in seen_this_run:
            skipped_seen += 1
            continue

        row = conn.execute("SELECT source, link FROM vulns WHERE key=?", (key,)).fetchone()
        if row:
            if row[0] is None or row[1] is None:
                _backfill_row(conn, key, it)
                backfilled += 1
            skipped_seen += 1
            seen_this_run.add(key)
            continue
        seen_this_run.add(key)

        hit, reason = score(it["text"])
        tag = _extract_id(it["text"], it["link"])
        cve_id = tag if tag != "N/A" else None
        conn.execute(
            "INSERT OR IGNORE INTO vulns (key,cve_id,source,title,link,summary,reason,pushed,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (key, cve_id, it["source"], it["title"][:300], it["link"],
             it["summary"][:500], reason, 1 if hit else 0, now),
        )
        if not hit:
            skipped_filter += 1
            continue

        ok = send_telegram(format_msg(it, reason))
        if ok:
            pushed += 1
        time.sleep(PUSH_SLEEP_SEC)

    conn.commit()
    db_cleanup(conn)
    total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
    conn.close()
    log.info(
        f"done: pushed={pushed}  filtered={skipped_filter}  already_seen={skipped_seen}  "
        f"backfilled={backfilled}  db_size={total}"
    )


# ================== TABLE FORMATTER ==================
def fmt_table(headers, rows):
    if not rows:
        print("(no results)")
        return
    all_rows = [headers] + rows
    widths = [max(len(str(c)) for c in col) for col in zip(*all_rows)]
    def fmt_row(r):
        return "  ".join(str(c).ljust(w) for c, w in zip(r, widths))
    print(fmt_row(headers))
    print("  ".join("─" * w for w in widths))
    for r in rows:
        print(fmt_row(r))


# ================== CLI: query ==================
def _query_rows(args, quality_filter=False):
    """Shared query logic — returns rows with all fields.

    quality_filter=True adds SQL-level gates for notification views:
      link IS NOT NULL, source IS NOT NULL, reason not in (no hit, excluded).
    """
    conn = _get_conn()
    init_db(conn)
    where, params = [], []
    if args.cve:
        where.append("cve_id LIKE ?"); params.append(f"%{args.cve}%")
    if args.source:
        where.append("source LIKE ?"); params.append(f"%{args.source}%")
    if args.keyword:
        where.append("(title LIKE ? OR summary LIKE ?)")
        params.extend([f"%{args.keyword}%"] * 2)
    if args.days:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=args.days)).timestamp()
        where.append("created_at > ?"); params.append(cutoff)
    if args.pushed:
        where.append("pushed = 1")
    if args.reason:
        where.append("reason LIKE ?"); params.append(f"%{args.reason}%")
    if quality_filter:
        where.append("link IS NOT NULL AND link != ''")
        where.append("source IS NOT NULL AND source != ''")
        if not args.reason:
            where.append("reason NOT IN ('no hit','excluded')")

    sql = "SELECT cve_id,source,title,link,summary,reason,pushed,created_at FROM vulns"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC"
    sql += f" LIMIT {args.limit}"

    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows

def cmd_query(args):
    rows = _query_rows(args)

    if args.json:
        out = []
        for cve, src, title, link, summary, reason, pushed, ts in rows:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None
            out.append({"id": cve, "source": src, "title": title, "url": link,
                        "summary": summary, "reason": reason, "pushed": bool(pushed), "date": dt})
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    if args.full:
        # one-record-per-block, human readable, all fields
        for i, (cve, src, title, link, summary, reason, pushed, ts) in enumerate(rows):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if ts else "-"
            if i > 0:
                print()
            print(f"[{src or '-'}] {cve or 'N/A'}  ({reason or '-'})  {dt}")
            print(f"  {title or '-'}")
            print(f"  {link or '(no url)'}")
            if summary:
                print(f"  {summary[:200]}")
        print(f"\n({len(rows)} rows)")
        return

    # default: compact table WITH url
    headers = ["ID", "Source", "Title", "URL", "Reason", "Date"]
    table = []
    for cve, src, title, link, summary, reason, pushed, ts in rows:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else "-"
        table.append([
            cve or "-", src or "-", (title or "")[:45],
            (link or "-")[:55], reason or "-", dt,
        ])
    fmt_table(headers, table)
    print(f"\n({len(rows)} rows)")


# ================== CLI: brief ==================
def cmd_brief(args):
    """Notification-friendly output: one block per vuln, copy-paste ready.

    Pipeline: _auto_enrich() → SQL quality filter → output.
    """
    enriched = _auto_enrich()
    explain = getattr(args, "explain", False)
    if explain:
        conn = _get_conn()
        init_db(conn)
        total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        no_link = conn.execute("SELECT COUNT(*) FROM vulns WHERE link IS NULL OR link=''").fetchone()[0]
        placeholders = ",".join("?" for _ in STRONG_REASONS)
        strong_no_link = conn.execute(
            f"SELECT COUNT(*) FROM vulns WHERE (link IS NULL OR link='') AND reason IN ({placeholders})",
            tuple(STRONG_REASONS),
        ).fetchone()[0]
        conn.close()
        print(f"[explain] enriched {enriched} records this pass")
        print(f"[explain] db total={total}  still_no_link={no_link}  strong_without_link={strong_no_link}")
        if strong_no_link:
            print(f"[explain] {strong_no_link} strong records could not be enriched (run 'rebuild' to fix from feeds)")
        print(f"[explain] quality filter: link NOT NULL, source NOT NULL, reason NOT IN (no hit, excluded)")
        print()
    rows = _query_rows(args, quality_filter=True)
    if not rows:
        print("(no results matching quality threshold)")
        return
    for i, (cve, src, title, link, summary, reason, pushed, ts) in enumerate(rows):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else "-"
        tag = cve or "N/A"
        if i > 0:
            print(f"{'─' * 60}")
        print(f"{tag}  [{src}]  {dt}")
        print(f"{title or '-'}")
        print(f"{link}")
        print(f"match: {reason or '-'}")
    print(f"\n({len(rows)} results)")


# ================== CLI: stats ==================
def cmd_stats(args):
    conn = _get_conn()
    init_db(conn)
    total   = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
    pushed  = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1").fetchone()[0]
    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).timestamp()
    recent  = conn.execute("SELECT COUNT(*) FROM vulns WHERE created_at>?", (day_ago,)).fetchone()[0]
    last_ts = conn.execute("SELECT MAX(created_at) FROM vulns").fetchone()[0]
    last_dt = datetime.fromtimestamp(last_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if last_ts else "-"
    print(f"Total: {total}  |  Pushed: {pushed}  |  Last 24h: {recent}  |  Last update: {last_dt}\n")

    sources = conn.execute("SELECT source,COUNT(*) FROM vulns GROUP BY source ORDER BY COUNT(*) DESC").fetchall()
    print("── By Source ──")
    fmt_table(["Source", "Count"], [[s or "(migrated)", str(n)] for s, n in sources])

    print()
    reasons = conn.execute(
        "SELECT reason,COUNT(*) FROM vulns WHERE pushed=1 GROUP BY reason ORDER BY COUNT(*) DESC"
    ).fetchall()
    print("── By Reason (pushed only) ──")
    fmt_table(["Reason", "Count"], [[r, str(n)] for r, n in reasons])
    conn.close()


# ================== CLI: rebuild ==================
def cmd_rebuild(args):
    """Re-fetch all sources and backfill NULL fields in existing records."""
    conn = _get_conn()
    init_db(conn)

    items = []
    for name, url in RSS_FEEDS:
        items.extend(fetch_rss(name, url))
    items.extend(fetch_kev_json())
    items.extend(fetch_github_cve())
    print(f"fetched {len(items)} items from sources")

    updated = 0
    for it in items:
        key = item_key(it["title"], it["link"], it["text"])
        row = conn.execute("SELECT source, link FROM vulns WHERE key=?", (key,)).fetchone()
        if row and (row[0] is None or row[1] is None):
            _backfill_row(conn, key, it)
            updated += 1

    conn.commit()
    # report remaining incomplete records
    incomplete = conn.execute(
        "SELECT COUNT(*) FROM vulns WHERE source IS NULL OR link IS NULL"
    ).fetchone()[0]
    conn.close()
    print(f"backfilled {updated} records")
    if incomplete:
        print(f"note: {incomplete} records still have NULL fields (source no longer in feeds)")


# ================== MAIN ==================
def main():
    parser = argparse.ArgumentParser(description="vuln-monitor: 0day/1day RCE intelligence")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("fetch", help="Fetch all sources, dedup, store, push")

    # shared filter args for query and brief
    def _add_filter_args(p):
        p.add_argument("--cve",     help="Filter by CVE ID (substring match)")
        p.add_argument("--source",  help="Filter by source name")
        p.add_argument("--keyword", "-k", help="Search title and summary")
        p.add_argument("--days",    type=int, help="Only last N days")
        p.add_argument("--pushed",  action="store_true", help="Only pushed items")
        p.add_argument("--reason",  help="Filter by match reason")
        p.add_argument("--limit",   type=int, default=50, help="Max rows (default 50)")

    qp = sub.add_parser("query", help="Query stored vulnerabilities")
    _add_filter_args(qp)
    qp.add_argument("--full",   action="store_true", help="Detailed multi-line output")
    qp.add_argument("--json",   action="store_true", help="JSON output")

    bp = sub.add_parser("brief", help="Notification-friendly output (human readable, with URL)")
    _add_filter_args(bp)
    bp.add_argument("--explain", action="store_true", help="Show enrichment/filter diagnostics")

    sub.add_parser("stats", help="Database statistics")
    sub.add_parser("rebuild", help="Re-fetch sources and backfill NULL fields in existing records")

    args = parser.parse_args()

    if args.cmd == "query":
        cmd_query(args)
    elif args.cmd == "brief":
        cmd_brief(args)
    elif args.cmd == "stats":
        cmd_stats(args)
    elif args.cmd == "rebuild":
        cmd_rebuild(args)
    else:
        # default / "fetch": original behavior
        try:
            with SingletonLock(LOCK_FILE):
                _run()
        except RuntimeError as ex:
            log.warning(str(ex))
            sys.exit(0)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("unhandled error")
            send_failure_alert(tb[-3500:])
            sys.exit(1)


if __name__ == "__main__":
    main()
