#!/usr/bin/env python3
"""Fetch CVE data from blog and update README.md."""

import json
import re
import urllib.request
from collections import OrderedDict
from html.parser import HTMLParser


class AboutPageParser(HTMLParser):
    """Parse the about page to extract vendor-grouped CVEs."""

    def __init__(self):
        super().__init__()
        self.in_vul_section = False
        self.current_vendor = None
        self.vendors = OrderedDict()
        self.current_tag = None
        self.current_attrs = {}
        self.current_href = None
        self.buffer = ""
        self.found_vul_header = False
        # Track bold/strong tags for vendor names
        self.in_bold = False
        self.bold_text = ""

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
        self.current_attrs = dict(attrs)
        if tag in ("b", "strong"):
            self.in_bold = True
            self.bold_text = ""
        if tag == "a":
            self.current_href = self.current_attrs.get("href", "")

    def handle_endtag(self, tag):
        if tag in ("b", "strong") and self.in_bold:
            self.in_bold = False
            if self.in_vul_section and self.bold_text.strip():
                vendor = self.bold_text.strip().rstrip(":")
                if vendor and not any(
                    skip in vendor.lower()
                    for skip in ["other", "tip", "0x300"]
                ):
                    self.current_vendor = vendor
                    if vendor not in self.vendors:
                        self.vendors[vendor] = []
                elif "other" in vendor.lower():
                    self.current_vendor = "Other"
                    if "Other" not in self.vendors:
                        self.vendors["Other"] = []
        if tag == "a":
            self.current_href = None
        self.current_tag = None

    def handle_data(self, data):
        if self.in_bold:
            self.bold_text += data

        # Detect VUL LIST header
        if "VUL LIST" in data:
            self.in_vul_section = True
            return

        if not self.in_vul_section:
            return

        # Extract CVEs from text
        cves = re.findall(r"CVE-\d{4}-\d{4,}", data)
        if cves and self.current_vendor:
            for cve in cves:
                href = self.current_href if self.current_tag == "a" else None
                entry = {"cve": cve, "url": href}
                # Avoid duplicates
                existing_cves = [e["cve"] for e in self.vendors.get(self.current_vendor, [])]
                if cve not in existing_cves:
                    if self.current_vendor not in self.vendors:
                        self.vendors[self.current_vendor] = []
                    self.vendors[self.current_vendor].append(entry)
        elif cves and not self.current_vendor:
            # CVEs before any vendor heading go to Other
            if "Other" not in self.vendors:
                self.vendors["Other"] = []
            for cve in cves:
                href = self.current_href if self.current_tag == "a" else None
                existing_cves = [e["cve"] for e in self.vendors["Other"]]
                if cve not in existing_cves:
                    self.vendors["Other"].append({"cve": cve, "url": href})


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


def update_readme(readme_path, cve_section, total):
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
    update_readme(readme_path, cve_section, total)
    print("Updated README.md")


if __name__ == "__main__":
    main()
