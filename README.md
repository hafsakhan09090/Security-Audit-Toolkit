# Security Audit Toolkit

A small Python command-line tool that audits a web application **you own or have written permission to test** for common transport and browser-security weaknesses, then turns each finding into a scored, prioritised risk register.

## What it does
- Makes **one normal GET request** (read-only, no exploitation, no scanning of other ports or hosts)
- Checks HTTPS use, security headers (HSTS, CSP, X-Content-Type-Options, clickjacking protection, Referrer-Policy, Permissions-Policy), version-banner disclosure and cookie flags (Secure, HttpOnly, SameSite)
- Scores each finding: **risk = likelihood (1-5) x impact (1-5)**, rated Low / Medium / High / Critical
- Maps each finding to a **NIST Cybersecurity Framework** function (Identify / Protect)
- Exports a Markdown report and a CSV risk register

## Usage
```bash
python security_audit.py https://your-own-site.example --confirm-authorized --md report.md --csv risk_register.csv
```
The `--confirm-authorized` flag is required. Only assess systems you own or are explicitly authorised to assess.

## Run the tests
```bash
pip install -r requirements.txt
pytest -v
```
Tests use a local HTTP server on `127.0.0.1`, so they never touch the internet.

## Design notes
- Uses only the Python standard library at runtime (`urllib`, `argparse`, `csv`, `dataclasses`)
- `analyze_response()` is a pure function, which keeps the checks unit-testable
- Example output rows: `High | 16 | HTTPS | Protect | Serve the site over HTTPS...`

## Ideas for next steps
- Add a TLS version and certificate-expiry check
- Add an OWASP Top 10 mapping column
- Export to JSON for ingestion into other tools
