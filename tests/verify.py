#!/usr/bin/env python3
"""Hidden verifier: reads /app/report.json, writes the reward to /logs/verifier."""
import json, os

REPORT = os.environ.get("REPORT_PATH", "/app/report.json")
OUT_DIR = os.environ.get("REWARD_DIR", "/logs/verifier")

EXPECTED = {
    "compromised_account": "t.wanjiru",
    "login_ip": "203.0.113.77",
    "exfil_ip": "203.0.113.140",
    "initial_access": "legacy_endpoint_no_mfa",
    "exfiltrated_file": "customer_ledger_2026Q3.csv",
}


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    try:
        with open(REPORT) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("report is not a JSON object")
    except Exception as e:
        print("report unreadable: %s" % e)
        data = {}

    correct = 0
    for key, want in EXPECTED.items():
        got = str(data.get(key, "")).strip()
        ok = got == want
        correct += ok
        print("%-20s %s" % (key, "OK" if ok else "WRONG"))

    score = correct / len(EXPECTED)
    with open(os.path.join(OUT_DIR, "reward.txt"), "w") as f:
        f.write("%.4f\n" % score)
    print("score: %.4f" % score)


if __name__ == "__main__":
    main()