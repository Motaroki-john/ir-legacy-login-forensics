#!/bin/bash
set -euo pipefail
python3 - <<'PY'
import collections, json, re

def field(pat, line):
    return re.search(pat, line).group(1)

sso = open("/var/log/sso/auth.log").read().splitlines()
ngx = open("/var/log/nginx/access.log").read().splitlines()
aud = [json.loads(l) for l in open("/var/log/app/audit.jsonl")]

ips = collections.defaultdict(set)
for l in ngx:
    m = re.search(r"sid=(s-[0-9a-f]+)", l)
    if m:
        ips[m.group(1)].add(l.split()[0])
multi = [s for s, v in ips.items() if len(v) > 1]
assert len(multi) == 1, multi
sid = multi[0]

login = [l for l in sso if "sid=" + sid in l][0]
rec = [r for r in aud if r["sid"] == sid and r["action"] == "export_download"][0]
exfil = [l for l in ngx if "rid=" + rec["request_id"] + " " in l][0]

weak = field(r"endpoint=(\S+)", login) == "/legacy/login" and field(r"mfa=(\S+)", login) == "none"
report = {
    "compromised_account": field(r"user=(\S+)", login),
    "login_ip": field(r"ip=(\S+)", login),
    "exfil_ip": exfil.split()[0],
    "initial_access": "legacy_endpoint_no_mfa" if weak else "unknown",
    "exfiltrated_file": rec["resource"],
}
json.dump(report, open("/app/report.json", "w"), indent=2)
print(json.dumps(report, indent=2))
PY