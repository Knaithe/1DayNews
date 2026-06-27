import sqlite3

conn = sqlite3.connect('/opt/vuln-monitor/vuln_cache.db')
conn.row_factory = sqlite3.Row

keywords = ['Tomcat','Laravel','Linux kernel','ksmbd','MantisBT','hashcat',
            'MQTT','OttoKit','VMware','Broadcom','Ivanti','Fortinet',
            'Palo Alto','Cisco','Apache','Microsoft','Windows','Outlook',
            'Exchange','vCenter','ESXi','OpenSSL','nginx','PHP ','WordPress',
            'Jenkins','Docker','Kubernetes','Redis','PostgreSQL','MySQL',
            'Grafana','GitLab','Jira','Confluence','SonarQube','Keycloak',
            'authentik','Harbor','Minio','RabbitMQ','Kafka','Elastic',
            'Kibana','Prometheus','Ansible','Terraform','HPLIP','Perl','Ruby']

rows = conn.execute('''
    SELECT cve_id, title, vuln_type, severity, cvss, llm_verdict, llm_notes,
           SUBSTR(summary, 1, 200) as summary_head, source
    FROM vulns
    WHERE llm_verdict IN ('noise', 'not_relevant')
      AND cvss >= 8.0
      AND pushed = 0
    ORDER BY cvss DESC
''').fetchall()

hits = []
for r in rows:
    text = (r['title'] or '') + ' ' + (r['summary_head'] or '') + ' ' + (r['llm_notes'] or '')
    text_lower = text.lower()
    matched = [kw for kw in keywords if kw.lower().strip() in text_lower]
    if matched:
        hits.append((r, matched))

print(f"Total noise/not_relevant cvss>=8: {len(rows)}")
print(f"Known-product false negatives: {len(hits)}")
print()
for r, kws in hits:
    cve = r['cve_id'] or '?'
    vt = r['vuln_type'] or '?'
    verdict = r['llm_verdict']
    cvss = r['cvss']
    title = (r['title'] or '')[:100]
    notes = (r['llm_notes'] or '')[:130]
    print(f"{cve:22s} cvss={cvss:4} [{vt:6s}] verdict={verdict}")
    print(f"  products: {', '.join(kws)}")
    print(f"  title: {title}")
    print(f"  LLM: {notes}")
    print()
conn.close()
