#!/usr/bin/env python3
"""
0day/1day RCE vulnerability intelligence aggregator.

Sources (17):
    Vendor PSIRT (Fortinet/PaloAlto/Cisco/MSRC) + Sploitus exploit feeds
    + research teams (watchTowr/ZDI/Horizon3/Rapid7) + CISA KEV
    + vuln databases (Chaitin/ThreatBook) + GitHub PoC search

Flow:
    fetch → dedup (SQLite, CVE/hash key) → RCE keyword score → Telegram push

CLI:
    python vuln_monitor.py              # fetch (default)
    python vuln_monitor.py query ...    # search DB
    python vuln_monitor.py brief ...    # notification-friendly output
    python vuln_monitor.py stats        # database overview
    python vuln_monitor.py rebuild      # backfill incomplete records
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
_raw_chat_id = os.getenv("TG_CHAT_ID")   or _user_cfg.get("tg_chat_id", "")
TG_CHAT_IDS  = [c.strip() for c in _raw_chat_id.split(",") if c.strip()]
GH_TOKEN     = os.getenv("GH_TOKEN")     or _user_cfg.get("gh_token", "")
NVD_API_KEY  = os.getenv("NVD_API_KEY") or _user_cfg.get("nvd_api_key", "")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY") or _user_cfg.get("deepseek_api_key", "")
OPENAI_API_KEY   = os.getenv("OPENAI_API_KEY")   or _user_cfg.get("openai_api_key", "")
LLM_MODEL    = os.getenv("LLM_MODEL")       or _user_cfg.get("llm_model", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL")   or _user_cfg.get("llm_base_url", "")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE") or _user_cfg.get("llm_temperature", "0.1"))
LLM_MAX_TOKENS  = int(os.getenv("LLM_MAX_TOKENS")    or _user_cfg.get("llm_max_tokens", "1024"))
LLM_TIMEOUT     = int(os.getenv("LLM_TIMEOUT")        or _user_cfg.get("llm_timeout", "60"))
LLM_MAX_CONTEXT = int(os.getenv("LLM_MAX_CONTEXT")    or _user_cfg.get("llm_max_context", "1048576"))
LLM_REASONING   = os.getenv("LLM_REASONING_EFFORT")   or _user_cfg.get("llm_reasoning_effort", "high")
LLM_TOP_P       = float(os.getenv("LLM_TOP_P")        or _user_cfg.get("llm_top_p", "0.9"))
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
    # ---- Sploitus keyword feeds (fill PSIRT gaps with exploit/PoC signal) ----
    ("Sploitus_Citrix",   "https://sploitus.com/rss?query=citrix"),
    ("Sploitus_Ivanti",   "https://sploitus.com/rss?query=ivanti"),
    ("Sploitus_F5",       "https://sploitus.com/rss?query=f5+big-ip"),
    # ---- research teams (vuln-focused, not blogs/marketing) ----
    ("watchTowr",   "https://labs.watchtowr.com/rss/"),
    ("ZDI",         "https://www.zerodayinitiative.com/rss/published/"),
    ("Horizon3",    "https://www.horizon3.ai/feed/"),
    ("Rapid7",      "https://www.rapid7.com/blog/rss/"),
    ("DailyCVE",    "https://dailycve.com/feed"),
    # VMware (blog/marketing, 0% CVE) — removed
    # ProjectDisc (product marketing, 0% CVE) — removed
    # GreyNoise (trend analysis, 10% CVE) — removed
    # SentinelLabs (research blog, 0% CVE) — removed
    # XuanwuLab (academic/research, low CVE density) — removed
]

# CISA KEV uses a JSON endpoint (1500+ entries with structured fields, not RSS).
KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Chaitin Stack vuldb — hidden JSON API behind SafeLine WAF.
# Requires Referer/Origin headers; rate-limited (one call per fetch cycle is fine).
CHAITIN_API_URL = "https://stack.chaitin.com/api/v2/vuln/list/"

# ThreatBook (微步在线) — public homePage endpoint, returns premium + highrisk vulns.
THREATBOOK_API_URL = "https://x.threatbook.com/v5/node/vul_module/homePage"


# ================== RCE PATTERNS ==================
RCE_PATTERNS = [
    # naming
    r"\bRCE\b", r"remote code execution", r"arbitrary (code|command) execution",
    r"execute arbitrary (code|command)", r"execution of arbitrary (code|command)",
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
    "watchTowr", "MSRC", "Horizon3", "Chaitin", "ThreatBook",
})
# Reasons that indicate a genuinely interesting finding.
STRONG_VULN_TYPES = frozenset({"RCE", "other"})

# ── Freshness (1day vs nday) ──
# 1day = 漏洞本体新近公开且处于可利用窗口期，值得立刻关注和防御的新鲜攻击面。
# 不是"任意新内容"：老洞新 PoC / 聚合站重新收录 / 老洞重炒 都不算 1day。
# Sources where publication inherently means the vulnerability is fresh.
FRESH_SOURCES = frozenset({
    "Fortinet", "PaloAlto", "Cisco", "MSRC",        # Vendor PSIRT
    "CISA_KEV",                                       # In-the-wild confirmation
    "ZDI", "watchTowr", "Horizon3", "Rapid7",        # Research teams
    "Chaitin", "ThreatBook",                           # Curated vuln databases
    "DailyCVE",                                        # Aggregator, but entries are day-of CVEs (not old rehash)
})
# Sources that aggregate/republish old vulns — need CVE year validation.
# Sploitus_*, GitHub, PoC-GitHub are implicitly NOT in FRESH_SOURCES.

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
    "Rapid7":       "https://www.rapid7.com/blog/",
    "Chaitin":      "https://stack.chaitin.com/vuldb/index",
    "ThreatBook":   "https://x.threatbook.com/nodev4/vul_intelligence/recentvuln",
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

_RETRY_ATTEMPTS = 3
_RETRY_DELAY = 3

def _get_with_retry(session, url, **kwargs):
    """GET with retry on transient failures."""
    for attempt in range(1, _RETRY_ATTEMPTS + 1):
        try:
            r = session.get(url, **kwargs)
            return r
        except (requests.ConnectionError, requests.Timeout) as ex:
            if attempt == _RETRY_ATTEMPTS:
                raise
            log.debug(f"retry {attempt}/{_RETRY_ATTEMPTS} for {url}: {ex}")
            time.sleep(_RETRY_DELAY)
    return None  # unreachable


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
            vuln_type  TEXT,
            freshness  TEXT,
            freshness_reason TEXT,
            pushed     INTEGER DEFAULT 0,
            created_at REAL NOT NULL,
            cve_published TEXT,
            severity      TEXT,
            cvss          REAL,
            llm_verified  INTEGER DEFAULT 0,
            llm_verdict   TEXT,
            llm_notes     TEXT,
            tg_sent       INTEGER DEFAULT 0
        )
    """)
    # migrate: add columns if missing (existing databases)
    _new_cols = []
    for col, typedef in [
        ("cve_published", "TEXT"),
        ("severity",      "TEXT"),
        ("cvss",          "REAL"),
        ("llm_verified",  "INTEGER DEFAULT 0"),
        ("llm_verdict",   "TEXT"),
        ("llm_notes",     "TEXT"),
        ("tg_sent",       "INTEGER DEFAULT 0"),
        ("freshness",     "TEXT"),
        ("freshness_reason", "TEXT"),
        ("vuln_type",     "TEXT"),
    ]:
        try:
            conn.execute(f"ALTER TABLE vulns ADD COLUMN {col} {typedef}")
            _new_cols.append(col)
        except sqlite3.OperationalError:
            pass
    # backfill tg_sent: mark already-pushed records as sent (only on first migration)
    if "tg_sent" in _new_cols:
        conn.execute("UPDATE vulns SET tg_sent = 1 WHERE pushed = 1")
    # backfill freshness + vuln_type + migrate legacy values (only on first migration)
    if "freshness" in _new_cols:
        conn.execute("UPDATE vulns SET freshness='nday', reason=SUBSTR(reason,6) WHERE reason LIKE 'nday:%'")
        conn.execute("UPDATE vulns SET freshness='1day' WHERE freshness IS NULL AND reason NOT IN ('excluded','no hit')")
        # migrate legacy llm_verdict values
        conn.execute("UPDATE vulns SET llm_verdict='confirmed' WHERE llm_verdict IN ('1day_rce','1day_high','fallback_regex')")
        conn.execute("UPDATE vulns SET llm_verdict='not_relevant' WHERE llm_verdict='1day_low'")
        conn.execute("UPDATE vulns SET llm_verdict='not_relevant' WHERE llm_verdict='nday'")
    # backfill vuln_type from reason (only on first migration)
    if "vuln_type" in _new_cols:
        conn.execute("UPDATE vulns SET vuln_type='RCE' WHERE reason LIKE '%RCE%'")
        conn.execute("UPDATE vulns SET vuln_type='other' WHERE vuln_type IS NULL AND reason NOT IN ('excluded','no hit')")
    # enforce hard locks on existing data: GitHub/nday must not remain pushed
    conn.execute("UPDATE vulns SET pushed=0 WHERE source IN ('GitHub','PoC-GitHub') AND pushed=1")
    conn.execute("UPDATE vulns SET pushed=0 WHERE freshness='nday' AND pushed=1")
    conn.commit()
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_id     ON vulns(cve_id)     WHERE cve_id IS NOT NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source     ON vulns(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON vulns(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pushed     ON vulns(pushed)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_verified ON vulns(llm_verified) WHERE llm_verified=0")
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
    # Match strong vuln types
    type_clauses = []
    type_params = []
    for t in STRONG_VULN_TYPES:
        type_clauses.append("vuln_type = ?")
        type_params.append(t)
    candidates = conn.execute(
        f"SELECT key, cve_id, source, title, link FROM vulns "
        f"WHERE (link IS NULL OR link = '') AND ({' OR '.join(type_clauses)})",
        type_params,
    ).fetchall()
    updated = 0
    for key, cve_id, source, title, link in candidates:
        new_cve, new_src, new_link = _enrich_record(cve_id, source, title, link)
        if new_link != link or new_src != source or new_cve != cve_id:
            conn.execute(
                "UPDATE vulns SET cve_id=COALESCE(cve_id,?), source=COALESCE(source,?), "
                "link=COALESCE(link,?) WHERE key=?",
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
# Pre-compile patterns into single combined regexes for performance.
_RCE_RE = re.compile("|".join(f"(?:{p})" for p in RCE_PATTERNS), re.I)
_EXCLUDE_RE = re.compile("|".join(f"(?:{p})" for p in EXCLUDE_PATTERNS), re.I)
_ASSET_KW_SET = frozenset(ASSET_KEYWORDS)

def score(text):
    """Score text for exploitability. Returns (hit, reason, vuln_type).

    reason: detailed match info (RCE+asset/CVE, asset+CVE, etc.)
    vuln_type: simplified classification (RCE / other / None)
    """
    if _EXCLUDE_RE.search(text):
        return False, "excluded", None
    low = text.lower()
    rce   = bool(_RCE_RE.search(text))
    asset = any(k in low for k in _ASSET_KW_SET)
    cve   = bool(CVE_RE.search(text))
    if rce and asset and cve:
        return True, "RCE+asset+CVE", "RCE"
    if rce and asset:
        return True, "RCE+asset", "RCE"
    if rce and cve:
        return True, "RCE+CVE", "RCE"
    if asset and cve:
        return True, "asset+CVE", "other"
    return False, "no hit", None


_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_FRESHNESS_DAYS = 60
_nvd_cache = {}       # cve_id → {"published":"YYYY-MM-DD","cvss":float,"severity":str} or "" or None
_nvd_detail_cache = {}  # full detail cache for LLM tools

def _nvd_detail(cve_id):
    """Query NVD for CVE detail. Returns dict or None.

    Returns: {"published": "YYYY-MM-DD", "cvss": float, "severity": str, "description": str}
    Cache: in-memory dict → NVD API. DB cache handled by caller.
    """
    cve_upper = cve_id.upper()
    # check full detail cache
    if cve_upper in _nvd_detail_cache:
        return _nvd_detail_cache[cve_upper] or None
    # check date-only cache (from _warm_nvd_cache)
    if cve_upper in _nvd_cache:
        cached = _nvd_cache[cve_upper]
        if cached is None or cached == "":
            return None
        # have date but need full detail — query NVD
    # query NVD (rate limit: 50 req/30s with key, 5 req/30s without)
    _nvd_sleep = 0.7 if NVD_API_KEY else 6.5
    time.sleep(_nvd_sleep)
    try:
        hdrs = {"User-Agent": "vuln-monitor/1.0 (security research)"}
        if NVD_API_KEY:
            hdrs["apiKey"] = NVD_API_KEY
        r = requests.get(_NVD_API, params={"cveId": cve_upper}, timeout=10, headers=hdrs)
        if r.status_code in (403, 429):
            # rate limited — DON'T cache, allow retry next cycle
            log.debug(f"NVD rate limited for {cve_upper}")
            return None
        if r.status_code != 200:
            _nvd_cache[cve_upper] = ""
            return None
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            _nvd_cache[cve_upper] = ""
            _nvd_detail_cache[cve_upper] = None
            return None
        cve_data = vulns[0]["cve"]
        # published date
        pub = cve_data.get("published", "")
        pub_str = None
        if pub:
            dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            pub_str = dt.strftime("%Y-%m-%d")
        # CVSS v3.1 (fallback to v3.0, then v2)
        cvss = None
        severity = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve_data.get("metrics", {}).get(metric_key, [])
            if metrics:
                cvss_data = metrics[0].get("cvssData", {})
                cvss = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "").lower()
                break
        if cvss and not severity:
            severity = "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
        # description
        descs = cve_data.get("descriptions", [])
        desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        detail = {"published": pub_str, "cvss": cvss, "severity": severity, "description": desc_en}
        _nvd_cache[cve_upper] = pub_str or ""
        _nvd_detail_cache[cve_upper] = detail
        return detail
    except Exception:
        _nvd_cache[cve_upper] = None
    return None

def _nvd_published_date(cve_id):
    """Thin wrapper: returns (datetime, "YYYY-MM-DD") or (None, None)."""
    detail = _nvd_detail(cve_id)
    if detail and detail.get("published"):
        pub_str = detail["published"]
        dt = datetime.fromisoformat(pub_str).replace(tzinfo=timezone.utc)
        return dt, pub_str
    return None, None

def _backfill_nvd_severity(conn):
    """Backfill severity and CVSS for records that have CVE but no severity."""
    batch = 100 if NVD_API_KEY else 20
    rows = conn.execute(
        "SELECT key, cve_id FROM vulns "
        "WHERE cve_id IS NOT NULL AND cve_id LIKE 'CVE-%' AND severity IS NULL "
        f"LIMIT {batch}"
    ).fetchall()
    updated = 0
    for key, cve_id in rows:
        # cve_id may contain multiple CVEs space-separated — try each until one has data
        cves = CVE_RE.findall(cve_id)
        detail = None
        for c in (cves or [cve_id]):
            detail = _nvd_detail(c.upper())
            if detail and detail.get("cvss"):
                break
        if detail and detail.get("cvss"):
            conn.execute(
                "UPDATE vulns SET severity=?, cvss=?, cve_published=COALESCE(cve_published,?) WHERE key=?",
                (detail["severity"], detail["cvss"], detail.get("published"), key))
            updated += 1
    if updated:
        conn.commit()
        log.info(f"backfill_nvd_severity: updated {updated} records")


# ================== LLM ENRICHMENT ==================
# System prompt: load from DATA_DIR/llm_prompt.txt if exists, else use default.
_LLM_PROMPT_FILE = DATA_DIR / "llm_prompt.txt"
_LLM_SYSTEM_PROMPT_DEFAULT = """You are a vulnerability intelligence analyst. Determine whether a vulnerability is genuine and worth alerting on.

## Verdict categories:
- confirmed: Genuine vulnerability affecting real, widely-deployed products. Worth pushing.
- not_relevant: Real vulnerability but low practical impact — requires authentication + local access, niche product (<1000 deployments), info disclosure only with no escalation path. Not worth pushing.
- noise: Not a real threat — fabricated CVE, personal project with 0 users, CTF/homework, marketing content, automated CVE reservation with no real impact.

## Rules:
1. Vendor PSIRTs (Fortinet/Cisco/PaloAlto/MSRC) are authoritative — if they publish an advisory, it's almost always "confirmed".
2. CVSS is a REFERENCE only. Unauthenticated RCE / command injection / SQL injection / auth bypass on widely-deployed products = "confirmed" regardless of CVSS score.
3. "not_relevant" requires ALL of: authenticated-only OR local-only, AND niche/low-impact product.
4. GitHub repos: check if the repo has actual exploit code vs empty placeholder. 0-star personal forks with no code = noise.
5. Linux kernel CVE from NVD/GitHub with no real-world exploit = usually noise.
6. Use tools to verify when title/summary is ambiguous.
7. If you find a public exploit/PoC, mention it in notes — this is valuable intelligence.

Output ONLY JSON (no markdown):
{"verdict": "confirmed|not_relevant|noise", "notes": "one-sentence rationale"}
"""

def _get_llm_prompt():
    """Load system prompt from file (if exists) or use default."""
    if _LLM_PROMPT_FILE.exists():
        try:
            custom = _LLM_PROMPT_FILE.read_text(encoding="utf-8").strip()
            if custom:
                return custom
        except Exception:
            pass
    return _LLM_SYSTEM_PROMPT_DEFAULT

_ENRICH_TOOLS = [
    {"type": "function", "function": {
        "name": "fetch_nvd_detail",
        "description": "Get NVD detail for a CVE: CVSS score, severity, full description, published date.",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
    }},
    {"type": "function", "function": {
        "name": "fetch_source_page",
        "description": "Fetch text content of a URL (advisory page, blog post). Returns first 2000 chars.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    }},
    {"type": "function", "function": {
        "name": "search_github",
        "description": "Search GitHub for PoC/exploit repositories related to a CVE.",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
    }},
    {"type": "function", "function": {
        "name": "search_chaitin",
        "description": "Search Chaitin Stack vuldb (Chinese vulnerability database) for details.",
        "parameters": {"type": "object", "properties": {"keyword": {"type": "string"}}, "required": ["keyword"]},
    }},
]

_VERDICT_PUSH = {"confirmed": 1, "not_relevant": 0, "noise": 0}

_GITHUB_SOURCES = frozenset({"GitHub", "PoC-GitHub"})

def _resolve_pushed(verdict, freshness, source):
    """Determine pushed value from LLM verdict, respecting hard constraints.

    Rules:
      - freshness must be '1day' to push — nday/None/unknown all locked 0
      - GitHub/PoC-GitHub → locked 0, candidate only
      - LLM can downgrade any record, but cannot override freshness or source trust
    """
    llm_wants_push = _VERDICT_PUSH.get(verdict, 0)
    # only 1day is pushable — nday, None (no CVE / unverified) all blocked
    if freshness != "1day":
        return 0
    if source in _GITHUB_SOURCES:
        return 0
    return llm_wants_push
_MAX_TOOL_ROUNDS = 5


def _get_llm_client():
    """Create OpenAI-compatible client. Returns (client, model) or (None, None)."""
    try:
        from openai import OpenAI
    except ImportError:
        log.error("openai package not installed. Run: pip install openai")
        return None, None
    api_key = DEEPSEEK_API_KEY or OPENAI_API_KEY
    if not api_key:
        return None, None
    if DEEPSEEK_API_KEY:
        base_url = LLM_BASE_URL or "https://api.deepseek.com"
        model = LLM_MODEL or "deepseek-chat"
    else:
        base_url = LLM_BASE_URL or "https://api.openai.com"
        model = LLM_MODEL or "gpt-4o-mini"
    # avoid double /v1 if user already included it in base_url
    base = base_url.rstrip("/")
    if not base.endswith("/v1"):
        base += "/v1"
    client = OpenAI(api_key=api_key, base_url=base, timeout=LLM_TIMEOUT)
    log.info(f"LLM client: model={model} base_url={base}")
    return client, model

_llm_client = None
_llm_model = None


_TOOL_MAX_OUTPUT = 3000  # truncate tool output to avoid blowing context

def _tool_fetch_nvd_detail(cve_id):
    detail = _nvd_detail(cve_id)
    if not detail:
        return '{"error": "not found in NVD"}'
    # truncate description to avoid huge output
    if detail.get("description"):
        detail["description"] = detail["description"][:1000]
    return json.dumps(detail, ensure_ascii=False)[:_TOOL_MAX_OUTPUT]

def _tool_fetch_source_page(url):
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": "vuln-monitor/1.0"})
        text = re.sub(r"<[^>]+>", " ", r.text)
        return re.sub(r"\s+", " ", text).strip()[:2000]
    except Exception as ex:
        return json.dumps({"error": str(ex)})

def _tool_search_github(cve_id):
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    try:
        r = _get_with_retry(SESS, "https://api.github.com/search/repositories",
            params={"q": f"{cve_id} in:name,description", "sort": "stars", "per_page": 5},
            headers=headers, timeout=15)
        if r.status_code != 200:
            return json.dumps({"error": f"HTTP {r.status_code}"})
        repos = [{"name": rr["full_name"], "desc": (rr.get("description") or "")[:200],
                  "stars": rr["stargazers_count"], "url": rr["html_url"]}
                 for rr in r.json().get("items", [])]
        return json.dumps(repos, ensure_ascii=False)[:_TOOL_MAX_OUTPUT]
    except Exception as ex:
        return json.dumps({"error": str(ex)})

def _tool_search_chaitin(keyword):
    s = requests.Session()
    try:
        s.headers.update({"User-Agent": "Mozilla/5.0", "Referer": "https://stack.chaitin.com/vuldb/index",
                          "Origin": "https://stack.chaitin.com", "Accept": "application/json"})
        r = s.get(CHAITIN_API_URL, params={"limit": 5, "offset": 0, "search": keyword}, timeout=15)
        if r.status_code != 200:
            return json.dumps({"error": f"HTTP {r.status_code}"})
        items = r.json().get("data", {}).get("list", [])
        return json.dumps([{"cve": v.get("cve_id", ""), "title": v.get("title", ""),
                            "severity": v.get("severity", ""), "summary": (v.get("summary") or "")[:300]}
                           for v in items], ensure_ascii=False)[:_TOOL_MAX_OUTPUT]
    except Exception as ex:
        return json.dumps({"error": str(ex)})
    finally:
        s.close()

_TOOL_DISPATCH = {
    "fetch_nvd_detail": _tool_fetch_nvd_detail,
    "fetch_source_page": _tool_fetch_source_page,
    "search_github": _tool_search_github,
    "search_chaitin": _tool_search_chaitin,
}


def _enrich_one(record):
    """Run LLM agent loop on one vulnerability. Returns (verdict, notes) or (None, None)."""
    global _llm_client, _llm_model
    if _llm_client is None:
        _llm_client, _llm_model = _get_llm_client()
    if _llm_client is None:
        return None, None

    key, cve_id, source, title, link, summary, reason, severity, cvss, *_ = record
    user_msg = (
        f"Assess this vulnerability:\n"
        f"CVE: {cve_id or 'N/A'}\nSource: {source}\nTitle: {title}\n"
        f"URL: {link or 'N/A'}\nSummary: {summary or 'N/A'}\n"
        f"Regex match: {reason}\nCVSS: {cvss or 'unknown'}\nSeverity: {severity or 'unknown'}"
    )
    # skip tools for high-trust sources with sufficient data — direct judgment is faster
    has_enough_context = (source in FRESH_SOURCES and (severity or cvss))
    if has_enough_context:
        user_msg += "\n\nYou have enough context from this PSIRT advisory. Do NOT call tools — respond with JSON verdict directly."
    messages = [{"role": "system", "content": _get_llm_prompt()},
                {"role": "user", "content": user_msg}]
    # rough token estimate: 1 token ≈ 4 chars. Reserve max_tokens for output.
    _ctx_budget = (LLM_MAX_CONTEXT - LLM_MAX_TOKENS) * 4
    use_tools = not has_enough_context
    max_rounds = _MAX_TOOL_ROUNDS if use_tools else 1
    try:
        for round_i in range(max_rounds):
            kwargs = {
                "model": _llm_model, "messages": messages,
                "max_tokens": LLM_MAX_TOKENS,
                "temperature": LLM_TEMPERATURE,
                "top_p": LLM_TOP_P,
            }
            if use_tools:
                kwargs["tools"] = _ENRICH_TOOLS
            if LLM_REASONING:
                kwargs["reasoning_effort"] = LLM_REASONING
            try:
                resp = _llm_client.chat.completions.create(**kwargs)
            except Exception as first_err:
                err_msg = str(first_err).lower()
                # some models don't support certain params — retry without
                for param in ("temperature", "top_p", "reasoning_effort", "tools"):
                    if param in err_msg:
                        kwargs.pop(param, None)
                        break
                else:
                    raise
                resp = _llm_client.chat.completions.create(**kwargs)
            choice = resp.choices[0]
            if choice.message.tool_calls and round_i < max_rounds - 1:
                messages.append(choice.message)
                for tc in choice.message.tool_calls:
                    fn = _TOOL_DISPATCH.get(tc.function.name)
                    try:
                        args = json.loads(tc.function.arguments)
                    except (json.JSONDecodeError, TypeError):
                        args = {}
                    result = fn(**args) if fn else json.dumps({"error": "unknown tool"})
                    # truncate tool result to fit context budget
                    total_chars = sum(len(str(m.get("content", "") if isinstance(m, dict) else getattr(m, "content", ""))) for m in messages)
                    remaining = max(500, _ctx_budget - total_chars)
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": result[:remaining]})
                continue
            # last round with pending tool_calls: force a verdict
            if choice.message.tool_calls:
                messages.append(choice.message)
                for tc in choice.message.tool_calls:
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": '{"note":"round limit, give verdict now"}'})
                resp = _llm_client.chat.completions.create(
                    model=_llm_model, messages=messages,
                    max_tokens=LLM_MAX_TOKENS, temperature=LLM_TEMPERATURE)
                choice = resp.choices[0]
            # final response
            content = (choice.message.content or "").strip()
            # strip markdown fences and prose prefix before JSON
            content = re.sub(r"^```json\s*", "", content)
            content = re.sub(r"```\s*$", "", content)
            # extract first JSON object if LLM added prose around it
            m = re.search(r'\{[^{}]*"verdict"[^{}]*\}', content)
            if m:
                content = m.group(0)
            try:
                data = json.loads(content)
                return data.get("verdict"), data.get("notes", "")
            except (json.JSONDecodeError, AttributeError):
                log.warning(f"LLM unparseable for {cve_id}: {content[:200]}")
                return None, None
        log.warning(f"LLM exceeded {max_rounds} rounds for {cve_id}")
    except Exception as ex:
        log.warning(f"LLM err for {cve_id}: {ex}")
    return None, None


def _warm_nvd_cache(conn):
    """Pre-load DB cve_published values into in-memory cache at startup."""
    _nvd_cache.clear()
    try:
        rows = conn.execute("SELECT cve_id, cve_published FROM vulns WHERE cve_published IS NOT NULL").fetchall()
        for cve_id, pub in rows:
            if cve_id and pub:
                _nvd_cache[cve_id] = pub
    except Exception:
        pass

def _is_fresh(source, text):
    """Is this a fresh vulnerability disclosure (1day), not an nday rehash?

    Returns (fresh: bool, pub_date_str: str or None, reason: str).
    reason explains WHY: old_cve / nvd_60d / high_trust_source / no_cve_low_trust.
    """
    cves = CVE_RE.findall(text)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=_FRESHNESS_DAYS)
    year = now.year
    latest_pub_str = None
    has_nvd_confirmed_recent = False
    has_recent_year = False
    for c in cves:
        pub_dt, pub_str = _nvd_published_date(c.upper())
        if pub_str:
            if latest_pub_str is None or pub_str > latest_pub_str:
                latest_pub_str = pub_str
            if pub_dt and pub_dt >= cutoff:
                has_nvd_confirmed_recent = True
        else:
            # NVD unavailable — track year for high-trust fallback only
            try:
                cve_year = int(c.split("-")[1])
                if cve_year >= year - 1:
                    has_recent_year = True
            except (IndexError, ValueError):
                pass
    # hard cutoff: if ALL CVEs are > 1 year old → nday
    if cves:
        all_old = True
        for c in cves:
            try:
                cve_year = int(c.split("-")[1])
                if cve_year >= year - 1:
                    all_old = False
                    break
            except (IndexError, ValueError):
                all_old = False
                break
        if all_old:
            return False, latest_pub_str, "old_cve"
    # high-trust sources: trust timeliness (NVD confirmed OR recent CVE year)
    if source in FRESH_SOURCES:
        return True, latest_pub_str, "high_trust_source"
    # low-trust sources: no CVE = can't verify
    if not cves:
        return False, None, "no_cve_low_trust"
    # low-trust with CVE: require actual NVD confirmation, year fallback not trusted
    if has_nvd_confirmed_recent:
        return True, latest_pub_str, "nvd_60d"
    return False, latest_pub_str, "nvd_60d"


# ================== SOURCES ==================
def fetch_rss(name, url):
    """Fetch with our own timeout (feedparser.parse(url) has no timeout control)."""
    out = []
    try:
        r = _get_with_retry(SESS, url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
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
        r = _get_with_retry(SESS, KEV_JSON_URL, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"KEV HTTP {r.status_code}")
            return out
        data = r.json()
        kev_cutoff = (datetime.now(timezone.utc) - timedelta(days=CACHE_TTL_DAYS)).strftime("%Y-%m-%d")
        for v in data.get("vulnerabilities", []):
            if v.get("dateAdded", "") < kev_cutoff:
                continue
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


def fetch_chaitin():
    """Chaitin Stack vuldb — Chinese vuln database (350k+ total, ~184 curated).

    Uses a hidden JSON API; fresh session + Referer header to pass SafeLine WAF.
    Default list returns curated high-risk items (~184), not the full database.
    API limited to ~15 results per call; used as supplementary source.
    """
    out = []
    s = requests.Session()
    try:
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://stack.chaitin.com/vuldb/index",
            "Origin": "https://stack.chaitin.com",
            "Accept": "application/json",
        })
        r = _get_with_retry(s, CHAITIN_API_URL,
                  params={"limit": ITEM_PER_FEED, "offset": 0},
                  timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"Chaitin HTTP {r.status_code}")
            return out
        data = r.json()
        for v in data.get("data", {}).get("list", []):
            ct_id = v.get("ct_id", "")
            cve = v.get("cve_id", "")
            title = v.get("title", "")
            severity = v.get("severity", "")
            summary = v.get("summary", "")
            refs = v.get("references", "")
            link = f"https://stack.chaitin.com/vuldb/detail/{v['id']}" if v.get("id") else ""
            full_title = f"[{severity.upper()}] {cve or ct_id} {title}"
            out.append({
                "source": "Chaitin",
                "title": full_title[:300],
                "link": link,
                "summary": summary[:500],
                "text": f"{full_title}\n{summary}\n{refs}",
            })
    except Exception as ex:
        log.warning(f"Chaitin err: {ex}")
    finally:
        s.close()
    return out


def fetch_threatbook():
    """微步在线 ThreatBook — premium + highrisk vuln listings."""
    out = []
    s = requests.Session()
    try:
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://x.threatbook.com/nodev4/vul_intelligence/recentvuln",
            "Origin": "https://x.threatbook.com",
            "Accept": "application/json",
        })
        r = _get_with_retry(s, THREATBOOK_API_URL, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"ThreatBook HTTP {r.status_code}")
            return out
        data = r.json().get("data", {})
        for section in ("premium", "highrisk"):
            for v in data.get(section, []):
                xve = v.get("id", "")
                name = v.get("vuln_name_zh", "")
                risk = v.get("riskLevel", "")
                poc = v.get("pocExist", False)
                affects = ", ".join(v.get("affects", []))
                pub_date = v.get("vuln_publish_time", "")
                link = f"https://x.threatbook.com/nodev4/vul_intelligence/{xve}" if xve else ""
                title = f"[{risk}] {xve} {name}"
                summary = f"affects: {affects}" if affects else ""
                if poc:
                    summary = f"PoC available. {summary}"
                out.append({
                    "source": "ThreatBook",
                    "title": title[:300],
                    "link": link,
                    "summary": summary[:500],
                    "text": f"{title}\n{summary}\n{affects}",
                })
    except Exception as ex:
        log.warning(f"ThreatBook err: {ex}")
    finally:
        s.close()
    return out


# NVD API is used only for cve_published date lookup (_nvd_published_date),
# NOT as an intelligence source. Raw NVD data is too noisy (kernel patches,
# personal project CVEs, etc.) and has no editorial curation.


def fetch_github_cve():
    out = []
    year = datetime.now().year
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    for q in (f"CVE-{year}-", f"CVE-{year - 1}-"):
        try:
            r = _get_with_retry(SESS,
                "https://api.github.com/search/repositories",
                params={"q": f"{q} in:name", "sort": "updated", "order": "desc", "per_page": 30},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                log.warning(f"GitHub {q} status {r.status_code}: {r.text[:150]}")
                continue
            for repo in r.json().get("items", []):
                stars = repo.get("stargazers_count", 0)
                if stars < 3:
                    continue
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


def fetch_poc_in_github():
    """nomi-sec/PoC-in-GitHub: latest commit diff → new PoC repos for recent CVEs."""
    out = []
    year = datetime.now().year
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    try:
        r = _get_with_retry(SESS,
            "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/commits/master",
            headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"PoC-in-GitHub HTTP {r.status_code}")
            return out
        files = r.json().get("files", [])
        for f in files:
            fname = f.get("filename", "")
            # only current/previous year CVEs (path: "2026/CVE-2026-xxxx.json")
            if not (fname.startswith(f"{year}/") or fname.startswith(f"{year-1}/")):
                continue
            cves = CVE_RE.findall(fname)
            if not cves:
                continue
            cve = cves[0].upper()
            raw_url = f.get("raw_url", "")
            # fetch the JSON to get PoC repo URLs
            if raw_url:
                try:
                    jr = SESS.get(raw_url, headers=headers, timeout=10)
                    if jr.status_code == 200:
                        repos = jr.json() if isinstance(jr.json(), list) else []
                        for repo in repos[:3]:
                            name = repo.get("full_name", "")
                            desc = repo.get("description") or ""
                            html_url = repo.get("html_url", "")
                            out.append({
                                "source": "PoC-GitHub",
                                "title": f"{cve} PoC: {name}",
                                "link": html_url,
                                "summary": desc[:500],
                                "text": f"{cve} {name}\n{desc}",
                            })
                except Exception:
                    pass
    except Exception as ex:
        log.warning(f"PoC-in-GitHub err: {ex}")
    return out


def _fetch_all_sources():
    """Collect items from all configured sources. Used by _run() and cmd_rebuild()."""
    items = []
    counts = {}
    for name, url in RSS_FEEDS:
        batch = fetch_rss(name, url)
        counts[name] = len(batch)
        items.extend(batch)
    for name, func in [("CISA_KEV", fetch_kev_json), ("Chaitin", fetch_chaitin),
                        ("ThreatBook", fetch_threatbook),
                        ("GitHub", fetch_github_cve), ("PoC-GitHub", fetch_poc_in_github)]:
        batch = func()
        counts[name] = len(batch)
        items.extend(batch)
    log.info("source counts: " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    return items


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
    if not (TG_BOT_TOKEN and TG_CHAT_IDS):
        log.info(f"[DRY] {msg[:500]}")
        return True
    ok = True
    for chat_id in TG_CHAT_IDS:
        try:
            r = SESS.post(
                f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": msg,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": False,
                },
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                log.warning(f"TG push {chat_id} {r.status_code}: {r.text[:200]}")
                ok = False
        except Exception as ex:
            log.warning(f"TG err {chat_id}: {ex}")
            ok = False
    return ok


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
    if not (TG_BOT_TOKEN and TG_CHAT_IDS):
        log.error(f"[ALERT-DRY] {msg[:500]}")
    else:
        for chat_id in TG_CHAT_IDS:
            try:
                SESS.post(
                    f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                    json={
                        "chat_id": chat_id,
                        "text": f"vuln-monitor error\n\n{msg[:3800]}",
                        "disable_web_page_preview": True,
                    },
                    timeout=REQUEST_TIMEOUT,
                )
            except Exception as ex:
                log.error(f"alert push {chat_id} failed: {ex}")
    state["last_alert_ts"] = now
    try:
        tmp = ALERT_STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, ALERT_STATE)
    except Exception as ex:
        log.warning(f"alert state save failed: {ex}")


# ================== MAIN ==================
def _run(no_push=False):
    conn = _get_conn()
    init_db(conn)
    migrate_json_cache(conn)
    _warm_nvd_cache(conn)
    now = datetime.now(timezone.utc).timestamp()

    # detect cold start: if DB is empty, this is initial seeding — suppress push
    _cold_start = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0] == 0

    items = _fetch_all_sources()
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

        # ── Exploitability (severity) ──
        hit, reason, vuln_type = score(it["text"])

        # ── Freshness — ALL records with CVE get cve_published + freshness ──
        cve_pub = None
        freshness = None
        fresh_reason = None
        if CVE_RE.search(it["text"]):
            fresh, cve_pub, fresh_reason = _is_fresh(it["source"], it["text"])
            freshness = "1day" if fresh else "nday"
            if hit and not fresh:
                hit = False
        elif it["source"] in FRESH_SOURCES:
            # high-trust source without CVE (e.g. Fortinet FG-IR)
            freshness = "1day"
            fresh_reason = "high_trust_source"
        elif hit:
            # low-trust source, no CVE → can't verify freshness
            freshness = "nday"
            fresh_reason = "no_cve_low_trust"
            hit = False

        tag = _extract_id(it["text"], it["link"])
        cve_id = tag if tag != "N/A" else None
        nvd = _nvd_detail_cache.get(cve_id.upper()) if cve_id and cve_id.startswith("CVE-") else None
        nvd_severity = nvd["severity"] if nvd else None
        nvd_cvss = nvd["cvss"] if nvd else None
        should_push = hit and freshness == "1day" and it["source"] not in _GITHUB_SOURCES
        conn.execute(
            "INSERT OR IGNORE INTO vulns (key,cve_id,source,title,link,summary,reason,vuln_type,freshness,freshness_reason,pushed,created_at,cve_published,severity,cvss) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, cve_id, it["source"], it["title"][:300], it["link"],
             it["summary"][:500], reason, vuln_type, freshness, fresh_reason,
             1 if should_push else 0, now, cve_pub, nvd_severity, nvd_cvss),
        )
        if should_push:
            pushed += 1
        else:
            skipped_filter += 1

    conn.commit()

    # cold start: mark all records as already sent to prevent initial flood
    if _cold_start:
        suppressed = conn.execute("UPDATE vulns SET tg_sent=1 WHERE pushed=1 AND tg_sent=0").rowcount
        conn.commit()
        if suppressed:
            log.info(f"cold start: suppressed {suppressed} initial notifications (seeding run)")

    db_cleanup(conn)
    total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
    log.info(
        f"done: pushed={pushed}  filtered={skipped_filter}  already_seen={skipped_seen}  "
        f"backfilled={backfilled}  db_size={total}"
    )

    # Send pending Telegram notifications (unless --no-push)
    if not no_push:
        _push_pending(conn)
    conn.close()


def _push_pending(conn):
    """Send Telegram for all pushed=1, tg_sent=0 records."""
    pending = conn.execute(
        "SELECT key, cve_id, source, title, link, summary, reason, llm_verdict, llm_notes "
        "FROM vulns WHERE pushed=1 AND tg_sent=0"
    ).fetchall()
    if not pending:
        return
    sent = 0
    for key, cve_id, source, title, link, summary, reason, verdict, notes in pending:
        it = {"source": source or "", "title": title or "", "link": link or "",
              "summary": summary or "", "text": f"{title or ''}\n{summary or ''}"}
        msg = format_msg(it, reason)
        ok = send_telegram(msg)
        if ok:
            conn.execute("UPDATE vulns SET tg_sent=1 WHERE key=?", (key,))
            sent += 1
        time.sleep(PUSH_SLEEP_SEC)
    conn.commit()
    if sent:
        log.info(f"push: sent {sent} Telegram notifications")


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
            where.append("reason NOT IN ('no hit','excluded') AND freshness != 'nday'")

    sql = "SELECT cve_id,source,title,link,summary,reason,pushed,created_at FROM vulns"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(args.limit)

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
        placeholders = ",".join("?" for _ in STRONG_VULN_TYPES)
        strong_no_link = conn.execute(
            f"SELECT COUNT(*) FROM vulns WHERE (link IS NULL OR link='') AND vuln_type IN ({placeholders})",
            tuple(STRONG_VULN_TYPES),
        ).fetchone()[0]
        conn.close()
        print(f"[explain] enriched {enriched} records this pass")
        print(f"[explain] db total={total}  still_no_link={no_link}  strong_without_link={strong_no_link}")
        if strong_no_link:
            print(f"[explain] {strong_no_link} strong records could not be enriched (run 'rebuild' to fix from feeds)")
        print(f"[explain] quality filter: link NOT NULL, source NOT NULL, reason NOT IN (no hit, excluded), freshness != nday")
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
def cmd_rescore(args):
    """Re-evaluate all records with current score() + _is_fresh() rules."""
    with SingletonLock(LOCK_FILE):
        _cmd_rescore_inner()

def _cmd_rescore_inner():
    conn = _get_conn()
    init_db(conn)
    _warm_nvd_cache(conn)
    # only rescore records NOT yet verified by LLM — don't override LLM verdicts
    rows = conn.execute("SELECT key, cve_id, source, title, link, summary, reason, pushed FROM vulns WHERE llm_verified=0").fetchall()
    upgraded = downgraded = unchanged = 0
    for key, cve_id, source, title, link, summary, old_reason, old_pushed in rows:
        text = f"{title or ''}\n{summary or ''}"

        hit, reason, vuln_type = score(text)
        cve_pub = None
        freshness = None
        fresh_reason = None
        if CVE_RE.search(text):
            fresh, cve_pub, fresh_reason = _is_fresh(source or "", text)
            freshness = "1day" if fresh else "nday"
            if hit and not fresh:
                hit = False
        elif source in FRESH_SOURCES:
            freshness = "1day"
            fresh_reason = "high_trust_source"
        elif hit:
            freshness = "nday"
            fresh_reason = "no_cve_low_trust"
            hit = False

        new_pushed = 1 if (hit and freshness == "1day" and source not in _GITHUB_SOURCES) else 0
        if reason != old_reason or new_pushed != old_pushed or cve_pub:
            conn.execute("UPDATE vulns SET reason=?, vuln_type=?, freshness=?, freshness_reason=?, pushed=?, cve_published=COALESCE(?,cve_published) WHERE key=?",
                        (reason, vuln_type, freshness, fresh_reason, new_pushed, cve_pub, key))
            if new_pushed > old_pushed:
                upgraded += 1
            elif new_pushed < old_pushed:
                downgraded += 1
            else:
                unchanged += 1  # reason changed but pushed same

    conn.commit()
    total = len(rows)
    same = total - upgraded - downgraded - unchanged
    conn.close()
    print(f"rescored {total} records: {upgraded} upgraded, {downgraded} downgraded, {unchanged} reason-changed, {same} unchanged")


def cmd_enrich(args):
    """LLM-based vulnerability enrichment: NVD severity + LLM agent + push."""
    with SingletonLock(LOCK_FILE):
        _cmd_enrich_inner(getattr(args, 'dry', False))

def _cmd_enrich_inner(dry=False):
    conn = _get_conn()
    init_db(conn)
    _warm_nvd_cache(conn)

    # Phase 1: NVD severity/CVSS backfill
    _backfill_nvd_severity(conn)

    # Phase 2: LLM enrichment
    api_key = DEEPSEEK_API_KEY or OPENAI_API_KEY
    if not api_key:
        log.info("enrich: no LLM API key, skipping LLM enrichment")
    else:
        candidates = conn.execute(
            "SELECT key, cve_id, source, title, link, summary, reason, severity, cvss, freshness "
            "FROM vulns WHERE llm_verified = 0 "
            "AND reason NOT IN ('excluded', 'no hit') "
            "ORDER BY created_at DESC LIMIT 500"
        ).fetchall()

        if candidates:
            # group by CVE to avoid duplicate LLM calls
            by_cve = {}
            no_cve = []
            for rec in candidates:
                cve_id = rec[1]
                if cve_id and cve_id.startswith("CVE-"):
                    by_cve.setdefault(cve_id, []).append(rec)
                else:
                    no_cve.append(rec)

            auto_approved = llm_processed = llm_errors = 0

            # auto-approve: any record from high-trust source + critical CVSS
            for cve_id, records in by_cve.items():
                rep = records[0]
                any_high_trust = any(r[2] in HIGH_PRIORITY_SOURCES for r in records)
                best_cvss = max((r[8] for r in records if r[8]), default=None)
                if any_high_trust and best_cvss and best_cvss >= 9.0:
                    for rec in records:
                        pushed_val = _resolve_pushed("confirmed", rec[9], rec[2])
                        conn.execute(
                            "UPDATE vulns SET llm_verified=1, llm_verdict='confirmed', "
                            "llm_notes='auto: high-trust + CVSS>=9.0', pushed=? WHERE key=?",
                            (pushed_val, rec[0]))
                    auto_approved += len(records)
                    continue

                # LLM enrichment
                verdict, notes = _enrich_one(rep)
                if verdict is None:
                    llm_errors += 1
                    continue
                for rec in records:
                    pushed_val = _resolve_pushed(verdict, rec[9], rec[2])
                    conn.execute(
                        "UPDATE vulns SET llm_verified=1, llm_verdict=?, llm_notes=?, pushed=? WHERE key=?",
                        (verdict, (notes or "")[:500], pushed_val, rec[0]))
                llm_processed += 1
                time.sleep(0.5)

            # non-CVE records
            for rec in no_cve:
                verdict, notes = _enrich_one(rec)
                if verdict is None:
                    llm_errors += 1
                    continue
                pushed_val = _resolve_pushed(verdict, rec[9], rec[2])
                conn.execute(
                    "UPDATE vulns SET llm_verified=1, llm_verdict=?, llm_notes=?, pushed=? WHERE key=?",
                    (verdict, (notes or "")[:500], pushed_val, rec[0]))
                llm_processed += 1
                time.sleep(0.5)

            conn.commit()
            log.info(f"enrich: auto={auto_approved} llm={llm_processed} errors={llm_errors}")

            # fallback: too many LLM errors → push regex-scored items
            if llm_errors > 3:
                fallback = conn.execute(
                    "UPDATE vulns SET llm_verified=1, llm_verdict='confirmed', llm_notes='fallback: LLM errors, regex-scored', pushed=1 "
                    "WHERE llm_verified=0 AND vuln_type IN ('RCE','other') "
                    "AND freshness='1day' AND source NOT IN ('GitHub','PoC-GitHub')"
                ).rowcount
                conn.commit()
                if fallback:
                    log.warning(f"enrich: LLM errors, fell back to regex for {fallback} records")
        else:
            log.info("enrich: no unverified candidates")

    # Phase 3: push pending
    if not dry:
        _push_pending(conn)
    conn.close()


def cmd_rebuild(args):
    """Re-fetch all sources and backfill NULL fields in existing records."""
    with SingletonLock(LOCK_FILE):
        _cmd_rebuild_inner()

def _cmd_rebuild_inner():
    conn = _get_conn()
    init_db(conn)

    items = _fetch_all_sources()
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
def cmd_daemon(args):
    """Long-running daemon: fetch → enrich → sleep → repeat."""
    interval = int(os.getenv("FETCH_INTERVAL", "300"))
    log.info(f"daemon started: interval={interval}s")
    while True:
        try:
            with SingletonLock(LOCK_FILE):
                _run(no_push=True)
                _cmd_enrich_inner()
        except RuntimeError as ex:
            log.warning(f"daemon skip (lock held): {ex}")
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("daemon error")
            send_failure_alert(f"daemon error:\n{tb[-3500:]}")
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="vuln-monitor: 0day/1day RCE intelligence")
    sub = parser.add_subparsers(dest="cmd")

    fp = sub.add_parser("fetch", help="Fetch all sources, dedup, store, push")
    fp.add_argument("--no-push", action="store_true", help="Do not send Telegram (for chained use with enrich)")

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
    sub.add_parser("rescore", help="Re-evaluate all records with current scoring rules")

    ep = sub.add_parser("enrich", help="LLM-based enrichment: NVD severity + AI verdict + push")
    ep.add_argument("--dry", action="store_true", help="Enrich but do not push to Telegram")

    sub.add_parser("daemon", help="Long-running: fetch+enrich loop (env FETCH_INTERVAL=300)")

    args = parser.parse_args()

    if args.cmd == "daemon":
        cmd_daemon(args)
    elif args.cmd == "query":
        cmd_query(args)
    elif args.cmd == "brief":
        cmd_brief(args)
    elif args.cmd == "stats":
        cmd_stats(args)
    elif args.cmd == "rebuild":
        cmd_rebuild(args)
    elif args.cmd == "rescore":
        cmd_rescore(args)
    elif args.cmd == "enrich":
        try:
            cmd_enrich(args)
        except RuntimeError as ex:
            log.warning(str(ex))
            sys.exit(0)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("enrich error")
            send_failure_alert(f"enrich failed:\n{tb[-3500:]}")
            sys.exit(1)
    else:
        # default / "fetch": original behavior
        try:
            with SingletonLock(LOCK_FILE):
                _run(no_push=getattr(args, 'no_push', False))
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
