#!/usr/bin/env python3
"""Security Audit Toolkit

A small command-line tool that audits a web application you own (or have written
permission to test) for common transport and browser-security weaknesses, then
turns each finding into a scored, prioritised risk register.

What it checks (read-only, one normal GET request):
  * HTTPS use
  * Security headers (HSTS, CSP, X-Content-Type-Options, clickjacking
    protection, Referrer-Policy, Permissions-Policy)
  * Information disclosure (Server / X-Powered-By version banners)
  * Cookie flags (Secure, HttpOnly, SameSite)

Each finding gets a likelihood (1-5) and impact (1-5). Risk score = likelihood x
impact, rated Low / Medium / High / Critical and mapped to a NIST Cybersecurity
Framework function.

Use only on systems you own or are explicitly authorised to assess.
"""
import argparse
import csv
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from datetime import date
from urllib.parse import urlparse


@dataclass
class Finding:
    check: str
    detail: str
    likelihood: int
    impact: int
    nist_function: str
    recommendation: str

    @property
    def score(self) -> int:
        return self.likelihood * self.impact

    @property
    def rating(self) -> str:
        return rate(self.score)


def rate(score: int) -> str:
    """Map a 1-25 risk score to a rating."""
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def _header_map(headers):
    """Lower-case header lookup from a list of (name, value) tuples."""
    out = {}
    for name, value in headers:
        out.setdefault(name.lower(), []).append(value)
    return out


def analyze_response(final_url, headers):
    """Return a list of Findings for a response. Pure function, easy to test."""
    h = _header_map(headers)
    findings = []
    is_https = urlparse(final_url).scheme == "https"

    if not is_https:
        findings.append(Finding(
            "HTTPS", "Page is served over plain HTTP, so traffic can be read or modified in transit.",
            4, 5, "Protect", "Serve the site over HTTPS and redirect all HTTP traffic."))

    if is_https and "strict-transport-security" not in h:
        findings.append(Finding(
            "Strict-Transport-Security", "HSTS header is missing, so downgrade attacks are easier.",
            3, 4, "Protect", "Add Strict-Transport-Security with a long max-age."))

    if "content-security-policy" not in h:
        findings.append(Finding(
            "Content-Security-Policy", "No CSP, so injected scripts are not restricted by the browser.",
            3, 4, "Protect", "Define a Content-Security-Policy that limits script and resource sources."))

    nosniff = any(v.strip().lower() == "nosniff" for v in h.get("x-content-type-options", []))
    if not nosniff:
        findings.append(Finding(
            "X-Content-Type-Options", "Missing 'nosniff', so browsers may MIME-sniff responses.",
            2, 3, "Protect", "Send X-Content-Type-Options: nosniff."))

    csp_value = " ".join(h.get("content-security-policy", [])).lower()
    if "x-frame-options" not in h and "frame-ancestors" not in csp_value:
        findings.append(Finding(
            "Clickjacking protection", "Neither X-Frame-Options nor CSP frame-ancestors is set.",
            3, 3, "Protect", "Set X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors."))

    if "referrer-policy" not in h:
        findings.append(Finding(
            "Referrer-Policy", "No Referrer-Policy, so full URLs may leak to other sites.",
            2, 2, "Protect", "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter)."))

    if "permissions-policy" not in h:
        findings.append(Finding(
            "Permissions-Policy", "No Permissions-Policy to limit browser features such as camera or location.",
            1, 2, "Protect", "Add a Permissions-Policy that disables unused features."))

    server = " ".join(h.get("server", []))
    powered = " ".join(h.get("x-powered-by", []))
    if re.search(r"\d", server) or powered:
        banner = (server + " " + powered).strip()
        findings.append(Finding(
            "Information disclosure", f"Version banner exposed: '{banner}'.",
            2, 2, "Identify", "Remove or genericise Server and X-Powered-By headers."))

    for cookie in h.get("set-cookie", []):
        name = cookie.split("=", 1)[0].strip()
        parts = [p.strip().lower() for p in cookie.split(";")[1:]]
        missing = []
        if is_https and "secure" not in parts:
            missing.append("Secure")
        if "httponly" not in parts:
            missing.append("HttpOnly")
        if not any(p.startswith("samesite") for p in parts):
            missing.append("SameSite")
        if missing:
            findings.append(Finding(
                f"Cookie flags ({name})", "Cookie is missing: " + ", ".join(missing) + ".",
                3, 4, "Protect", "Set Secure, HttpOnly and SameSite on session and sensitive cookies."))

    return sorted(findings, key=lambda f: f.score, reverse=True)


def fetch(url, timeout=10):
    """Make one GET request and return (final_url, headers list)."""
    req = urllib.request.Request(url, headers={"User-Agent": "security-audit-toolkit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.geturl(), list(resp.headers.items())
    except urllib.error.HTTPError as err:  # still useful: error pages carry headers
        return err.geturl(), list(err.headers.items())


def to_markdown(target, findings):
    lines = [
        "# Security Audit Report",
        "",
        f"- Target: {target}",
        f"- Date: {date.today().isoformat()}",
        f"- Findings: {len(findings)}",
        "",
        "| Rating | Score | Check | NIST CSF | Recommendation |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.rating} | {f.score} | {f.check} | {f.nist_function} | {f.recommendation} |")
    if not findings:
        lines.append("| - | - | No findings | - | - |")
    return "\n".join(lines) + "\n"


def to_csv(path, findings):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["rating", "score", "check", "detail", "likelihood", "impact",
                         "nist_function", "recommendation"])
        for f in findings:
            writer.writerow([f.rating, f.score, f.check, f.detail, f.likelihood, f.impact,
                             f.nist_function, f.recommendation])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Audit a web app you own for common security weaknesses.")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--confirm-authorized", action="store_true",
                        help="Confirm you own the target or have written permission to assess it.")
    parser.add_argument("--csv", help="Write the risk register to this CSV file.")
    parser.add_argument("--md", help="Write a Markdown report to this file.")
    args = parser.parse_args(argv)

    if not args.confirm_authorized:
        print("Refusing to run: add --confirm-authorized to confirm you own the target "
              "or have written permission to assess it.", file=sys.stderr)
        return 2

    final_url, headers = fetch(args.url)
    findings = analyze_response(final_url, headers)
    report = to_markdown(args.url, findings)
    print(report)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(report)
    if args.csv:
        to_csv(args.csv, findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
