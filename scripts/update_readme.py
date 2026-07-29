#!/usr/bin/env python3
"""Fetch CVE data from blog and update README.md."""

import json
import re
import urllib.request
from collections import OrderedDict
from html.parser import HTMLParser


class AboutPageParser(HTMLParser):
    """Parse the about page to extract vendor-grouped CVEs.

    The blog groups CVEs under an ``<h2>VUL LIST</h2>`` section, with each
    vendor introduced by an ``<h3>Vendor</h3>`` heading followed by a list of
    ``<a class="cve-badge" href="...">CVE-...</a>`` (or link-less ``<span>``)
    badges.
    """

    def __init__(self):
        super().__init__()
        self.in_vul_section = False
        self.current_vendor = None
        self.vendors = OrderedDict()
        self.current_href = None
        # Track h3 headings for vendor names
        self.in_h3 = False
        self.h3_text = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "h3":
            self.in_h3 = True
            self.h3_text = ""
        elif tag == "a":
            self.current_href = attrs.get("href")

    def handle_endtag(self, tag):
        if tag == "h3" and self.in_h3:
            self.in_h3 = False
            if self.in_vul_section:
                vendor = self.h3_text.strip()
                if vendor:
                    self.current_vendor = vendor
                    self.vendors.setdefault(vendor, [])
        elif tag == "a":
            self.current_href = None

    def handle_data(self, data):
        if self.in_h3:
            self.h3_text += data

        # Detect VUL LIST header (lives in an <h2>, before any vendor <h3>)
        if "VUL LIST" in data:
            self.in_vul_section = True
            return

        if not self.in_vul_section:
            return

        # Extract CVEs from the current badge's text
        cves = re.findall(r"CVE-\d{4}-\d{4,}", data)
        if not cves:
            return

        vendor = self.current_vendor or "Other"
        self.vendors.setdefault(vendor, [])
        existing = {e["cve"] for e in self.vendors[vendor]}
        for cve in cves:
            if cve not in existing:
                self.vendors[vendor].append({"cve": cve, "url": self.current_href})
                existing.add(cve)


def fetch_page(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse_cves_from_html(html):
    parser = AboutPageParser()
    parser.feed(html)
    return parser.vendors


def fallback_parse_cves(html):
    """Fallback: just extract all CVEs and group by known vendors via context."""
    vendor_patterns = OrderedDict([
        ("HUAWEI", r"huawei"),
        ("DrayTek", r"draytek|vigor"),
        ("QNAP", r"qnap"),
        ("CISCO", r"cisco"),
        ("D-Link", r"d-?link"),
        ("ZYXEL", r"zyxel"),
        ("XIAOMI", r"xiaomi|mi\.com"),
        ("Synology", r"synology"),
        ("Linux Kernel", r"linux|kernel|redhat|vulert"),
        ("Netgear", r"netgear"),
        ("ASUS", r"asus"),
    ])

    vendors = OrderedDict()
    for v in vendor_patterns:
        vendors[v] = []
    vendors["Other"] = []

    # Find all CVEs with surrounding context
    for match in re.finditer(r'(?:href=["\']([^"\']*)["\'][^>]*>)?\s*(CVE-\d{4}-\d{4,})', html):
        url, cve = match.group(1), match.group(2)
        # Look at surrounding context (200 chars before)
        start = max(0, match.start() - 200)
        context = html[start:match.end()].lower()

        placed = False
        for vendor, pattern in vendor_patterns.items():
            if re.search(pattern, context):
                existing = [e["cve"] for e in vendors[vendor]]
                if cve not in existing:
                    vendors[vendor].append({"cve": cve, "url": url})
                placed = True
                break
        if not placed:
            existing = [e["cve"] for e in vendors["Other"]]
            if cve not in existing:
                vendors["Other"].append({"cve": cve, "url": url})

    # Remove empty vendors
    return OrderedDict((k, v) for k, v in vendors.items() if v)


def filter_empty_vendors(vendors):
    """Remove vendors with no CVEs."""
    return OrderedDict((k, v) for k, v in vendors.items() if v)


def generate_cve_section(vendors):
    lines = []
    total = sum(len(v) for v in vendors.values())

    for vendor, cves in vendors.items():
        cve_strs = []
        for entry in cves:
            if entry["url"]:
                cve_strs.append(f'[{entry["cve"]}]({entry["url"]})')
            else:
                cve_strs.append(entry["cve"])
        lines.append(f"**{vendor}**: {' | '.join(cve_strs)}")
        lines.append("")

    return total, "\n".join(lines)


def generate_impact_summary(total, vendor_counts):
    """Generate the compact research-impact sentence shown near the profile intro."""
    active_vendors = sum(1 for count in vendor_counts.values() if count)
    kernel_count = vendor_counts.get("Linux Kernel", 0)
    return (
        f"> **{total} public CVEs** across **{active_vendors} ecosystems**, "
        f"including **{kernel_count} Linux kernel findings**.<br>"
        f"**公开披露 {total} 个 CVE**，覆盖 **{active_vendors} 个研究生态**，"
        f"其中包括 **{kernel_count} 个 Linux 内核漏洞**。"
    )


def update_readme(readme_path, cve_section, total, vendor_counts=None):
    with open(readme_path, "r") as f:
        content = f.read()

    # Replace between markers
    pattern = r"(<!-- CVE_START -->).*?(<!-- CVE_END -->)"
    replacement = f"\\1\n{cve_section}\n\\2"
    content = re.sub(pattern, replacement, content, flags=re.DOTALL)

    # Update badge count
    content = re.sub(
        r"(https://img\.shields\.io/badge/CVEs-)\d+(\+?-)",
        f"\\g<1>{total}\\2",
        content,
    )

    # Update the concise impact line used by the redesigned profile.
    if vendor_counts is not None:
        impact_pattern = r"(<!-- IMPACT_START -->).*?(<!-- IMPACT_END -->)"
        impact = generate_impact_summary(total, vendor_counts)
        content = re.sub(
            impact_pattern,
            f"\\1\n{impact}\n\\2",
            content,
            flags=re.DOTALL,
        )

    with open(readme_path, "w") as f:
        f.write(content)


def main():
    blog_url = "https://bestwing.me/about/"
    readme_path = "README.md"

    print(f"Fetching {blog_url} ...")
    html = fetch_page(blog_url)

    print("Parsing CVEs ...")
    vendors = parse_cves_from_html(html)

    # If HTML parser didn't get good results, use fallback
    total_parsed = sum(len(v) for v in vendors.values())
    if total_parsed < 10:
        print("HTML parser got few results, using fallback parser ...")
        vendors = fallback_parse_cves(html)

    # Remove vendors with no CVE entries (e.g. Synology only has acknowledgement)
    vendors = filter_empty_vendors(vendors)

    total, cve_section = generate_cve_section(vendors)
    print(f"Found {total} CVEs across {len(vendors)} vendors")

    # Write cve-count.json
    vendor_counts = {k: len(v) for k, v in vendors.items()}
    with open("cve-count.json", "w") as f:
        json.dump({"count": total, "vendors": vendor_counts}, f, indent=2)
    print("Updated cve-count.json")

    # Update README
    update_readme(readme_path, cve_section, total, vendor_counts)
    print("Updated README.md")


if __name__ == "__main__":
    main()
