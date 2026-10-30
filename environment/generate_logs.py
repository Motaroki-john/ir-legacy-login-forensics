#!/usr/bin/env python3
"""Seeded synthetic log generator (stdlib only).
  python generate_logs.py --out /var/log
  python generate_logs.py --out ./_out --answers ./_answers.json   # dev only
"""
import argparse, json, os, random
from datetime import datetime, timedelta, timezone

SEED = 20261030

SC = {
    "office_ip": "192.0.2.10",
    "ops_ip": "198.51.100.200",
    "contractor_ip": "198.51.100.55",
    "reporting_ip": "198.51.100.201",
    "spray_ip": "198.51.100.23",
    "scanner_ip": "192.0.2.99",
    "login_ip": "203.0.113.77",
    "exfil_ip": "203.0.113.140",
    "victim": "t.wanjiru",
    "exfil_file": "customer_ledger_2026Q3.csv",
    "decoy_file": "reports_2026Q3.zip",
    "contractor_file": "vendor_recon_2026Q3.csv",
    "vector": "legacy_endpoint_no_mfa",
}
USERS = ["a.otieno", "b.kamau", "c.njeri", "d.mutua", "e.achieng", "f.wekesa",
         "g.kiprop", "h.abdi", "i.mwangi", "j.omondi", "k.chebet", "l.barasa",
         "m.wafula", "n.akinyi", "o.ndegwa", "p.langat", "q.mohamed",
         "r.cheruiyot", "s.kariuki", "t.wanjiru", "u.owino", "v.mbugua"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) Safari/605.1.15",
       "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"]
ACTIONS = [("view_account", "GET", "/api/v1/accounts/{id}"),
           ("list_transactions", "GET", "/api/v1/transactions?account={id}"),
           ("update_profile", "PUT", "/api/v1/profile"),
           ("download_statement", "GET", "/api/v1/statements/{id}.pdf")]


def iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def build(seed):
    rng = random.Random(seed)
    start = datetime(2026, 10, 26, tzinfo=timezone.utc)  # Monday
    nginx, audit, sso = [], [], []

    def rid():
        return "%016x" % rng.getrandbits(64)

    def new_sid():
        return "s-%012x" % rng.getrandbits(48)

    def req(ts, ip, method, path, status, size, ua,
            sid=None, user=None, action=None, res=None):
        r = rid()
        nginx.append((ts, '%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s" rid=%s sid=%s' % (
            ip, ts.strftime("%d/%b/%Y:%H:%M:%S +0000"), method, path,
            status, size, ua, r, sid or "-")))
        if user:
            audit.append((ts, json.dumps({
                "ts": iso(ts), "request_id": r, "sid": sid, "user": user,
                "action": action, "resource": res, "status": status})))

    def login(ts, user, ip, ep, result, mfa):
        sid = new_sid() if result == "success" else None
        sso.append((ts, "%s sso login user=%s ip=%s endpoint=%s result=%s mfa=%s sid=%s" % (
            iso(ts), user, ip, ep, result, mfa, sid or "-")))
        return sid

    ua_of = {u: rng.choice(UAS) for u in USERS}

    # --- normal traffic, nightly backups, legit legacy/no-MFA accounts ---
    for d in range(5):
        day = start + timedelta(days=d)
        stamp = day.strftime("%Y%m%d")

        t = day + timedelta(hours=1, minutes=rng.randint(0, 5))
        sid = login(t, "svc-backup", SC["ops_ip"], "/sso/token", "success", "n/a")
        fname = "nightly_backup_%s.tar" % stamp
        req(t + timedelta(seconds=5), SC["ops_ip"], "GET",
            "/api/v1/exports/%s/download" % fname, 200,
            rng.randint(2_000_000, 3_500_000), "backup-agent/1.4",
            sid, "svc-backup", "export_download", fname)

        t = day + timedelta(hours=2, minutes=rng.randint(0, 8))
        sid = login(t, "svc-reporting", SC["reporting_ip"],
                    "/legacy/login", "success", "none")
        req(t + timedelta(seconds=5), SC["reporting_ip"], "GET",
            "/api/v1/reports/daily", 200, rng.randint(8_000, 30_000),
            "report-runner/0.9", sid, "svc-reporting", "report_run", "daily")

        t = day + timedelta(hours=8, minutes=rng.randint(0, 40))
        sid = login(t, "c.ouma", SC["contractor_ip"],
                    "/legacy/login", "success", "none")
        for _ in range(rng.randint(3, 8)):
            t += timedelta(seconds=rng.randint(30, 900))
            aid = rng.randint(1000, 9999)
            req(t, SC["contractor_ip"], "GET",
                "/api/v1/transactions?account=%d" % aid, 200,
                rng.randint(400, 20_000), "vendor-portal/2.1",
                sid, "c.ouma", "list_transactions", str(aid))
        if d == 2:
            t += timedelta(seconds=60)
            req(t, SC["contractor_ip"], "GET",
                "/api/v1/exports/%s/download" % SC["contractor_file"], 200,
                4_194_304, "vendor-portal/2.1",
                sid, "c.ouma", "export_download", SC["contractor_file"])

        for u in USERS:
            if rng.random() < 0.1:
                continue
            t = day + timedelta(hours=7, minutes=rng.randint(30, 150))
            sid = login(t, u, SC["office_ip"], "/sso/login", "success", "totp")
            for _ in range(rng.randint(5, 25)):
                t += timedelta(seconds=rng.randint(20, 1200))
                name, method, path = rng.choice(ACTIONS)
                aid = rng.randint(1000, 9999)
                size = (rng.randint(40_000, 300_000) if name == "download_statement"
                        else rng.randint(400, 20_000))
                status = rng.choices([200, 304, 404, 500], [90, 6, 3, 1])[0]
                req(t, SC["office_ip"], method, path.format(id=aid), status,
                    size, ua_of[u], sid, u, name, str(aid))

    # --- decoy: password spray, Tue 03:10, all fail ---
    t = start + timedelta(days=1, hours=3, minutes=10)
    targets = USERS + ["admin", "root"]
    for i in range(60):
        t += timedelta(seconds=rng.randint(10, 25))
        login(t, targets[i % len(targets)], SC["spray_ip"],
              "/legacy/login", "fail", "none")
        req(t, SC["spray_ip"], "POST", "/legacy/login", 401, 112,
            "python-requests/2.31.0")

    # --- decoy: scanner, Tue 14:00 ---
    junk = ["/wp-login.php", "/.env", "/admin", "/phpmyadmin/",
            "/.git/config", "/server-status", "/backup.zip"]
    t = start + timedelta(days=1, hours=14)
    for _ in range(40):
        t += timedelta(seconds=rng.randint(5, 40))
        req(t, SC["scanner_ip"], "GET", rng.choice(junk),
            rng.choice([403, 404]), rng.randint(150, 600), "curl/8.5.0")

    # --- real attack, Wed 02:41: login from one IP, exfil from another ---
    v, lip, eip = SC["victim"], SC["login_ip"], SC["exfil_ip"]
    t = start + timedelta(days=2, hours=2, minutes=41)
    sid = login(t, v, lip, "/legacy/login", "success", "none")
    req(t, lip, "POST", "/legacy/login", 200, 640, ua_of[v], sid)
    for _ in range(rng.randint(8, 12)):
        t += timedelta(seconds=rng.randint(5, 40))
        name, method, path = rng.choice(ACTIONS[:2])
        aid = rng.randint(1000, 9999)
        req(t, lip, method, path.format(id=aid), 200,
            rng.randint(400, 20_000), ua_of[v], sid, v, name, str(aid))
    t += timedelta(seconds=30)
    req(t, eip, "GET", "/api/v1/exports", 200, 2_100, ua_of[v],
        sid, v, "list_exports", "exports")
    t += timedelta(seconds=45)
    req(t, eip, "GET", "/api/v1/exports/%s/download" % SC["exfil_file"], 200,
        12_582_912, ua_of[v], sid, v, "export_download", SC["exfil_file"])

    # --- decoy: benign admin, bigger export, Wed 23:30 ---
    t = start + timedelta(days=2, hours=23, minutes=30)
    sid = login(t, "admin.ops", SC["ops_ip"], "/sso/login", "success", "totp")
    req(t + timedelta(minutes=2), SC["ops_ip"], "GET",
        "/api/v1/exports/%s/download" % SC["decoy_file"], 200, 50_331_648,
        UAS[0], sid, "admin.ops", "export_download", SC["decoy_file"])

    answers = {
        "compromised_account": v,
        "login_ip": lip,
        "exfil_ip": eip,
        "initial_access": SC["vector"],
        "exfiltrated_file": SC["exfil_file"],
    }
    return nginx, audit, sso, answers


def write(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows.sort(key=lambda r: r[0])  # stable
    with open(path, "w") as f:
        f.write("\n".join(r[1] for r in rows) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/var/log")
    ap.add_argument("--answers")
    ap.add_argument("--seed", type=int, default=SEED)
    a = ap.parse_args()
    nginx, audit, sso, answers = build(a.seed)
    write(os.path.join(a.out, "nginx", "access.log"), nginx)
    write(os.path.join(a.out, "app", "audit.jsonl"), audit)
    write(os.path.join(a.out, "sso", "auth.log"), sso)
    if a.answers:
        with open(a.answers, "w") as f:
            json.dump(answers, f, indent=2)