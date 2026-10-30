# Incident Response: Suspected Account Takeover

You are an incident responder at a fintech company. On Wednesday 28 October 2026 the security team was alerted to a possible account takeover on the customer portal, followed by a bulk data export.

Logs for the week of Monday 26 October 2026 are available in the container. All timestamps are UTC.

- `/var/log/sso/auth.log`: single sign-on login events
- `/var/log/nginx/access.log`: web server access log
- `/var/log/app/audit.jsonl`: application audit log (one JSON object per line)

The environment contains normal user activity, service accounts, a contractor, scanners, and other unrelated noise. Not everything unusual in the logs is part of the incident.

## Task

Determine what happened and write your findings to `/app/report.json` as a single JSON object with exactly these string fields:

| Field | Meaning |
|---|---|
| `compromised_account` | Username of the account that was taken over |
| `login_ip` | IP address from which the attacker's session was established |
| `exfil_ip` | IP address from which the data export was performed |
| `initial_access` | How the attacker got in. One of: `password_spray`, `phishing`, `leaked_api_token`, `vulnerable_upload`, `legacy_endpoint_no_mfa`, `insider` |
| `exfiltrated_file` | Filename of the file the attacker downloaded |

Example of the format (values are placeholders, not hints):

```json
{
  "compromised_account": "user.name",
  "login_ip": "192.0.2.1",
  "exfil_ip": "192.0.2.2",
  "initial_access": "insider",
  "exfiltrated_file": "file.csv"
}
```

Do not modify the log files. Only the contents of `/app/report.json` are evaluated. Each field is scored independently.