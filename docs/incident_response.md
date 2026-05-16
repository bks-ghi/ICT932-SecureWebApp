# Incident Response Plan

## Project: ICT932-SecureWebApp
## Author: Trian

---

## Simulated Incident 1: Brute-Force Login Attack

### Description
An attacker repeatedly attempts to guess a user's password by trying many combinations.

### Detection
- Logger flags repeated failed login attempts
- Log entry example: `WARNING - Failed login attempt for username: admin`

### Response Steps
1. **Identify** — Review `logs/app_YYYYMMDD.log` for repeated failures from same username
2. **Contain** — Implement account lockout after 5 failed attempts
3. **Eradicate** — Reset affected account credentials
4. **Recover** — Re-enable account after identity verification via email
5. **Post-Incident** — Document findings, update detection thresholds

### OWASP Reference
- A07:2021 – Identification and Authentication Failures

---

## Simulated Incident 2: Unauthorized Admin Access Attempt

### Description
A regular user attempts to access the `/admin` route directly.

### Detection
- Logger flags unauthorized access attempt
- Log entry example: `WARNING - Unauthorized admin access by username: john`

### Response Steps
1. **Identify** — Check logs for `Unauthorized admin access` warnings
2. **Contain** — RBAC automatically blocks access and redirects to dashboard
3. **Eradicate** — Review user account for suspicious activity
4. **Recover** — No recovery needed if RBAC blocked successfully
5. **Post-Incident** — Confirm RBAC is correctly enforced on all admin routes

### OWASP Reference
- A01:2021 – Broken Access Control

---

## Logging Location
All security events are logged to: logs/app_YYYYMMDD.log

## Monitored Events
| Event | Log Level | Action |
|-------|-----------|--------|
| Failed login | WARNING | Monitor for brute force |
| Successful login | INFO | Normal |
| Admin access denied | WARNING | Investigate immediately |
| 2FA failure | WARNING | Monitor for bypass attempts |
| New user registered | INFO | Normal |