"""
MSRC source — polls the Microsoft Security Response Center CVRF API
for Patch Tuesday updates and identifies kernel/driver CVEs.

Workflow:
  1. Fetch monthly update list from /cvrf/v3.0/updates
  2. For new months, fetch full CVRF XML
  3. Parse for kernel/driver CVEs (EoP, RCE in kernel components)
  4. Cross-reference affected drivers with WinBIndex watchlist
  5. Return enriched CVE entries for the driver monitor to act on
"""

import logging
import re
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"

# Products that indicate kernel-mode components.
# Matches against CVRF ProductTree FullProductName values.
KERNEL_PRODUCT_PATTERNS = [
    r"windows.*kernel",
    r"win32k",
    r"ntoskrnl",
    r"kernel streaming",
    r"ancillary function driver",
    r"common log file",
    r"tcp/ip",
    r"http protocol stack",
    r"ntfs",
    r"fat file system",
    r"cloud files mini filter",
    r"client-side caching",
    r"applocker",
    r"cryptographic",
]

# CVE title patterns that suggest kernel-mode driver vulnerabilities.
DRIVER_TITLE_PATTERNS = [
    re.compile(r"windows\s+kernel", re.I),
    re.compile(r"win32k", re.I),
    re.compile(r"ntfs|fat\s+file\s+system", re.I),
    re.compile(r"kernel\s+streaming", re.I),
    re.compile(r"ancillary\s+function\s+driver|afd\.sys", re.I),
    re.compile(r"tcp/ip|tcpip", re.I),
    re.compile(r"http\s+protocol\s+stack|http\.sys", re.I),
    re.compile(r"common\s+log\s+file|clfs", re.I),
    re.compile(r"cloud\s+files\s+mini\s+filter|cldflt", re.I),
    re.compile(r"client.side\s+caching|csc\.sys", re.I),
    re.compile(r"applocker|appid", re.I),
    re.compile(r"ndis|network\s+driver", re.I),
    re.compile(r"smb.*server|srv2", re.I),
    re.compile(r"\.sys\b", re.I),
    re.compile(r"elevation\s+of\s+privilege.*kernel", re.I),
    re.compile(r"kernel.*elevation\s+of\s+privilege", re.I),
]

# Impact types we care about.
RELEVANT_IMPACTS = {"Elevation of Privilege", "Remote Code Execution", "Information Disclosure"}

# CVRF XML namespace
NS = {"cvrf": "http://www.icasi.org/CVRF/schema/cvrf/1.1",
      "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1",
      "prod": "http://www.icasi.org/CVRF/schema/prod/1.1"}


def poll(
    redis_client,
    known_key: str,
    processed_prefix: str = "autopiff:monitor:msrc_months",
    max_months: int = 3,
) -> List[Dict]:
    """
    Poll MSRC for recent Patch Tuesday updates and extract kernel/driver CVEs.

    Returns list of dicts:
      {cve_id, title, impact, max_severity, driver_hint, msrc_url, update_id}

    Only returns CVEs from months not yet processed (tracked in Redis).
    """
    new_cves = []

    # Step 1: Get list of available monthly updates
    try:
        resp = requests.get(f"{MSRC_API_BASE}/updates", timeout=30)
        resp.raise_for_status()
        updates = resp.json().get("value", [])
    except Exception as e:
        logger.error(f"MSRC: failed to fetch update list: {e}")
        return []

    # Sort by ID (e.g. "2026-Feb") to get most recent first
    updates.sort(key=lambda u: u.get("ID", ""), reverse=True)

    # Step 2: Process the most recent N unprocessed months
    months_processed = 0
    for update in updates:
        if months_processed >= max_months:
            break

        update_id = update.get("ID", "")
        if not update_id:
            continue

        # Skip already-processed months
        if redis_client.sismember(processed_prefix, update_id):
            continue

        logger.info(f"MSRC: processing update {update_id}")

        # Step 3: Fetch CVRF XML for this month
        cves = _fetch_and_parse_cvrf(update_id)
        if cves is None:
            continue

        # Step 4: Filter for kernel/driver CVEs
        for cve in cves:
            cve_id = cve["cve_id"]
            cache_key = f"autopiff:monitor:msrc_cves:{cve_id}"

            if redis_client.sismember(known_key, cache_key):
                continue

            new_cves.append(cve)
            redis_client.sadd(known_key, cache_key)

        # Mark this month as processed
        redis_client.sadd(processed_prefix, update_id)
        months_processed += 1

    logger.info(f"MSRC poll complete: {len(new_cves)} new kernel/driver CVE(s)")
    return new_cves


def _fetch_and_parse_cvrf(update_id: str) -> Optional[List[Dict]]:
    """Fetch CVRF XML for a monthly update and extract kernel/driver CVEs."""
    try:
        resp = requests.get(
            f"{MSRC_API_BASE}/cvrf/{update_id}",
            timeout=60,
            headers={"Accept": "application/xml"},
        )
        resp.raise_for_status()
    except Exception as e:
        logger.error(f"MSRC: failed to fetch CVRF for {update_id}: {e}")
        return None

    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as e:
        logger.error(f"MSRC: failed to parse CVRF XML for {update_id}: {e}")
        return None

    results = []

    # Find all Vulnerability entries
    for vuln in root.findall(".//vuln:Vulnerability", NS):
        cve_el = vuln.find("vuln:CVE", NS)
        title_el = vuln.find("vuln:Title", NS)

        if cve_el is None or cve_el.text is None:
            continue

        cve_id = cve_el.text.strip()
        title = title_el.text.strip() if title_el is not None and title_el.text else ""

        # Check if this is a kernel/driver CVE by title
        if not _is_kernel_driver_cve(title):
            continue

        # Extract impact type
        impact = ""
        for threat in vuln.findall("vuln:Threats/vuln:Threat", NS):
            threat_type = threat.get("Type", "")
            if threat_type == "0":  # Impact
                desc = threat.find("vuln:Description", NS)
                if desc is not None and desc.text:
                    impact = desc.text.strip()
                    break

        # Filter by relevant impact types
        if impact and impact not in RELEVANT_IMPACTS:
            continue

        # Extract max severity
        max_severity = ""
        for threat in vuln.findall("vuln:Threats/vuln:Threat", NS):
            threat_type = threat.get("Type", "")
            if threat_type == "3":  # Severity
                desc = threat.find("vuln:Description", NS)
                if desc is not None and desc.text:
                    sev = desc.text.strip()
                    if sev in ("Critical", "Important"):
                        max_severity = sev
                    break

        # Extract exploitability (is it exploited ITW?)
        exploited = False
        for threat in vuln.findall("vuln:Threats/vuln:Threat", NS):
            threat_type = threat.get("Type", "")
            if threat_type == "1":  # Exploitability
                desc = threat.find("vuln:Description", NS)
                if desc is not None and desc.text:
                    if "Exploitation Detected" in desc.text:
                        exploited = True
                    break

        # Try to infer driver name from title
        driver_hint = _extract_driver_hint(title)

        results.append({
            "cve_id": cve_id,
            "title": title,
            "impact": impact,
            "max_severity": max_severity,
            "exploited_itw": exploited,
            "driver_hint": driver_hint,
            "msrc_url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
            "update_id": update_id,
        })

    logger.info(f"MSRC: {update_id} → {len(results)} kernel/driver CVEs")
    return results


def _is_kernel_driver_cve(title: str) -> bool:
    """Check if a CVE title refers to a kernel-mode driver component."""
    for pattern in DRIVER_TITLE_PATTERNS:
        if pattern.search(title):
            return True
    return False


def _extract_driver_hint(title: str) -> str:
    """Try to infer the affected driver filename from the CVE title."""
    title_lower = title.lower()

    driver_map = {
        "win32k": "win32k.sys",
        "kernel streaming server": "mskssrv.sys",
        "kernel streaming wow": "ksthunk.sys",
        "kernel streaming": "ks.sys",
        "ancillary function driver": "afd.sys",
        "tcp/ip": "tcpip.sys",
        "http protocol stack": "http.sys",
        "common log file": "clfs.sys",
        "clfs": "clfs.sys",
        "cloud files mini filter": "cldflt.sys",
        "client-side caching": "csc.sys",
        "applocker": "appid.sys",
        "ntfs": "ntfs.sys",
        "fat file system": "fastfat.sys",
        "smb": "srv2.sys",
        "ndis": "ndis.sys",
    }

    for keyword, driver in driver_map.items():
        if keyword in title_lower:
            return driver

    # Check for explicit .sys references
    sys_match = re.search(r'(\w+\.sys)', title_lower)
    if sys_match:
        return sys_match.group(1)

    # Generic kernel
    if "kernel" in title_lower:
        return "ntoskrnl.exe"

    return ""
