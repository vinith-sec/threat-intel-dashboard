"""
Threat Intel Aggregator Dashboard
===================================
Aggregates open-source threat intelligence from AbuseIPDB and
AlienVault OTX into a unified IOC lookup with severity scoring
and CSV export.

Author : Vinith Kumaragurubaran | github.com/vinith-sec
License: MIT
"""

import os
import re
import csv
import json
import time
import argparse
import datetime
import requests
from pathlib import Path


ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
OTX_API_KEY   = os.getenv("OTX_API_KEY",   "")

# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
def abuseipdb_check(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"source": "AbuseIPDB", "ioc": ip, "error": "ABUSEIPDB_KEY not set"}
    url     = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "source":             "AbuseIPDB",
                "ioc":                ip,
                "ioc_type":           "ip",
                "abuse_confidence":   d.get("abuseConfidenceScore", 0),
                "total_reports":      d.get("totalReports", 0),
                "country":            d.get("countryCode", "N/A"),
                "isp":                d.get("isp", "N/A"),
                "domain":             d.get("domain", "N/A"),
                "is_tor":             d.get("isTor", False),
                "is_public":          d.get("isPublic", True),
                "last_reported":      d.get("lastReportedAt", "N/A"),
                "usage_type":         d.get("usageType", "N/A"),
            }
        return {"source": "AbuseIPDB", "ioc": ip, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "AbuseIPDB", "ioc": ip, "error": str(e)}


# ── AlienVault OTX ────────────────────────────────────────────────────────────
def otx_check_ip(ip: str) -> dict:
    if not OTX_API_KEY:
        return {"source": "OTX", "ioc": ip, "error": "OTX_API_KEY not set"}
    url     = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            d = r.json()
            pulses = d.get("pulse_info", {})
            return {
                "source":       "OTX",
                "ioc":          ip,
                "ioc_type":     "ip",
                "pulse_count":  pulses.get("count", 0),
                "pulse_names":  [p.get("name", "") for p in pulses.get("pulses", [])[:3]],
                "tags":         d.get("tags", [])[:5],
                "reputation":   d.get("reputation", 0),
                "country":      d.get("country_name", "N/A"),
                "asn":          d.get("asn", "N/A"),
            }
        return {"source": "OTX", "ioc": ip, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "OTX", "ioc": ip, "error": str(e)}


def otx_check_domain(domain: str) -> dict:
    if not OTX_API_KEY:
        return {"source": "OTX", "ioc": domain, "error": "OTX_API_KEY not set"}
    url     = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            d = r.json()
            pulses = d.get("pulse_info", {})
            return {
                "source":      "OTX",
                "ioc":         domain,
                "ioc_type":    "domain",
                "pulse_count": pulses.get("count", 0),
                "pulse_names": [p.get("name", "") for p in pulses.get("pulses", [])[:3]],
                "tags":        d.get("tags", [])[:5],
                "alexa_rank":  d.get("alexa", "N/A"),
            }
        return {"source": "OTX", "ioc": domain, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "OTX", "ioc": domain, "error": str(e)}


def otx_check_hash(file_hash: str) -> dict:
    if not OTX_API_KEY:
        return {"source": "OTX", "ioc": file_hash, "error": "OTX_API_KEY not set"}
    url     = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            d = r.json()
            pulses = d.get("pulse_info", {})
            return {
                "source":      "OTX",
                "ioc":         file_hash,
                "ioc_type":    "hash",
                "pulse_count": pulses.get("count", 0),
                "pulse_names": [p.get("name", "") for p in pulses.get("pulses", [])[:3]],
                "malware_families": d.get("malware_families", [])[:3],
            }
        return {"source": "OTX", "ioc": file_hash, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "OTX", "ioc": file_hash, "error": str(e)}


# ── IOC type detection ────────────────────────────────────────────────────────
IP_RE     = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
HASH_RE   = re.compile(r'^[0-9a-fA-F]{32,64}$')
DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')

def detect_ioc_type(ioc: str) -> str:
    if IP_RE.match(ioc):
        return "ip"
    if HASH_RE.match(ioc):
        return "hash"
    if DOMAIN_RE.match(ioc):
        return "domain"
    return "unknown"


# ── Severity scoring ──────────────────────────────────────────────────────────
def score_ioc(results: list) -> dict:
    """Aggregate results from multiple sources into a unified severity score."""
    score = 0
    flags = []

    for r in results:
        if "error" in r:
            continue
        if r.get("source") == "AbuseIPDB":
            conf = r.get("abuse_confidence", 0)
            score += conf * 0.4
            if conf >= 80:
                flags.append(f"AbuseIPDB confidence {conf}% (HIGH)")
            elif conf >= 50:
                flags.append(f"AbuseIPDB confidence {conf}% (MEDIUM)")
            if r.get("is_tor"):
                score += 20; flags.append("TOR exit node")
            if r.get("total_reports", 0) > 100:
                score += 10; flags.append(f"{r['total_reports']} abuse reports")

        if r.get("source") == "OTX":
            pulses = r.get("pulse_count", 0)
            if pulses > 0:
                score += min(pulses * 5, 40)
                flags.append(f"Found in {pulses} OTX threat intelligence pulse(s)")
            for name in r.get("malware_families", []):
                flags.append(f"Malware family: {name}")

    score = min(int(score), 100)
    verdict = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    return {"score": score, "verdict": verdict, "flags": flags}


# ── Lookup pipeline ───────────────────────────────────────────────────────────
def lookup_ioc(ioc: str) -> dict:
    ioc_type = detect_ioc_type(ioc.strip())
    results  = []

    print(f"  [{ioc_type.upper()}] {ioc}")

    if ioc_type == "ip":
        results.append(abuseipdb_check(ioc))
        results.append(otx_check_ip(ioc))
    elif ioc_type == "domain":
        results.append(otx_check_domain(ioc))
    elif ioc_type == "hash":
        results.append(otx_check_hash(ioc))
    else:
        print(f"    [!] Unknown IOC type — skipping")
        return {"ioc": ioc, "ioc_type": "unknown", "score": {"score": 0, "verdict": "UNKNOWN", "flags": []}, "results": []}

    time.sleep(1)   # be polite to APIs
    score_data = score_ioc(results)
    return {"ioc": ioc, "ioc_type": ioc_type, "score": score_data, "results": results}


def lookup_batch(iocs: list) -> list:
    print(f"\n[*] Looking up {len(iocs)} IOC(s)...\n")
    return [lookup_ioc(ioc) for ioc in iocs]


# ── Display ───────────────────────────────────────────────────────────────────
VERDICT_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}

def print_dashboard(results: list):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    print("\n" + "=" * 70)
    print("  THREAT INTEL AGGREGATOR DASHBOARD")
    print(f"  Generated: {now}")
    print("=" * 70)

    for entry in sorted(results, key=lambda x: x["score"]["score"], reverse=True):
        verdict = entry["score"]["verdict"]
        icon    = VERDICT_ICON.get(verdict, "⚪")
        print(f"\n{icon} [{verdict}] {entry['ioc']}  (Score: {entry['score']['score']}/100)")
        print(f"   Type: {entry['ioc_type'].upper()}")

        for flag in entry["score"]["flags"]:
            print(f"   ⚠  {flag}")

        for r in entry["results"]:
            if "error" in r:
                print(f"   [{r['source']}] Error: {r['error']}")
            elif r.get("source") == "AbuseIPDB":
                print(f"   [AbuseIPDB] Confidence: {r.get('abuse_confidence')}% | "
                      f"ISP: {r.get('isp','N/A')} | Country: {r.get('country','N/A')} | "
                      f"TOR: {r.get('is_tor', False)}")
            elif r.get("source") == "OTX":
                pulses = r.get("pulse_names", [])
                pulse_str = ", ".join(pulses[:2]) if pulses else "None"
                print(f"   [OTX] Pulses: {r.get('pulse_count', 0)} | Related: {pulse_str}")

        print("   " + "─" * 66)

    # Summary
    verdicts = [e["score"]["verdict"] for e in results]
    print(f"\n  SUMMARY — {len(results)} IOCs analyzed")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = verdicts.count(level)
        if count:
            print(f"  {VERDICT_ICON[level]} {level}: {count}")
    print("=" * 70 + "\n")


# ── Export ────────────────────────────────────────────────────────────────────
def export_csv(results: list, output_path: str):
    fieldnames = [
        "ioc", "ioc_type", "verdict", "score",
        "flags", "abuseipdb_confidence", "abuseipdb_isp",
        "abuseipdb_country", "is_tor", "otx_pulses", "otx_pulse_names",
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for entry in results:
            row = {
                "ioc":      entry["ioc"],
                "ioc_type": entry["ioc_type"],
                "verdict":  entry["score"]["verdict"],
                "score":    entry["score"]["score"],
                "flags":    " | ".join(entry["score"]["flags"]),
            }
            for r in entry["results"]:
                if r.get("source") == "AbuseIPDB":
                    row["abuseipdb_confidence"] = r.get("abuse_confidence", "")
                    row["abuseipdb_isp"]        = r.get("isp", "")
                    row["abuseipdb_country"]    = r.get("country", "")
                    row["is_tor"]               = r.get("is_tor", "")
                if r.get("source") == "OTX":
                    row["otx_pulses"]       = r.get("pulse_count", "")
                    row["otx_pulse_names"]  = " | ".join(r.get("pulse_names", []))
            writer.writerow(row)
    print(f"[✓] CSV exported → {output_path}")


def export_json(results: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[✓] JSON exported → {output_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Threat Intel Aggregator Dashboard — unified IOC lookup from AbuseIPDB + OTX"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ioc",  help="Single IOC to look up (IP, domain, or hash)")
    group.add_argument("--file", help="Text file with one IOC per line")

    parser.add_argument("--export-csv",  help="Export results to CSV")
    parser.add_argument("--export-json", help="Export results to JSON")
    args = parser.parse_args()

    if args.ioc:
        iocs = [args.ioc.strip()]
    else:
        with open(args.file) as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    results = lookup_batch(iocs)
    print_dashboard(results)

    if args.export_csv:
        export_csv(results, args.export_csv)
    if args.export_json:
        export_json(results, args.export_json)


if __name__ == "__main__":
    main()
