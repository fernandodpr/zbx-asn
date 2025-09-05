#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Zabbix ASN Tools (zbx-asn)
# Copyright (C) 2025  Fernando de Peroy Rodríguez
# https://github.com/fernandodpr/zbx-asn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import bisect
import ipaddress
import json
import os
import sys
from typing import List, Optional, Set, Tuple
from collections import Counter

import requests

DEFAULT_ZABBIX_URL = os.getenv("ZABBIX_URL", "")
DEFAULT_TAG_KEY_ASN = "ASN"
DEFAULT_TAG_KEY_NAME = "ASN_NAME"
DEFAULT_TIMEOUT = 10
DEFAULT_BATCH = 200
DEFAULT_IP2ASN_TSV = "ip2asn-combined.tsv"

# ------------------- utilities -------------------

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def is_public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return getattr(ip, "is_global", False)

def merge_tags(existing_tags: List[dict], key: str, new_value: str) -> List[dict]:
    merged = [t for t in (existing_tags or []) if t.get("tag") != key]
    merged.append({"tag": key, "value": new_value})
    return merged

def _norm_list_str(s: str) -> List[str]:
    if not s:
        return []
    items = [x.strip() for x in s.split(",")]
    norm = []
    seen = set()
    for it in items:
        if not it:
            continue
        key = it.casefold()
        if key not in seen:
            seen.add(key)
            norm.append(it)
    norm.sort(key=lambda x: x.casefold())
    return norm

def _tags_get_value(tags: List[dict], key: str) -> str:
    for t in tags or []:
        if t.get("tag") == key:
            return t.get("value") or ""
    return ""

def collect_host_ips(host: dict) -> List[str]:
    ips: Set[str] = set()
    host_field = (host.get("host") or "").strip()
    if is_ip(host_field):
        ips.add(host_field)
    for itf in (host.get("interfaces") or []):
        ip = (itf.get("ip") or "").strip()
        if ip and is_ip(ip):
            ips.add(ip)
    return sorted(ips, key=lambda s: (':' in s, s))  # IPv4 first

# ------------------- IP classification -------------------

def ip_class(ip: str) -> str:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return "NA"
    if obj.version == 6:
        return "IPv6"
    first = int(str(obj).split(".")[0])
    if 1 <= first <= 126:
        return "A"
    if 128 <= first <= 191:
        return "B"
    if 192 <= first <= 223:
        return "C"
    if 224 <= first <= 239:
        return "D"
    if 240 <= first <= 255:
        return "E"
    return "NA"

def private_range(ip: str) -> str:
    """Return private/special range for v4/v6 IPs (with /24 granularity for v4 private)."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return "INVALID"

    if obj.version == 4:
        if obj in ipaddress.ip_network("10.0.0.0/8"):
            return str(ipaddress.ip_network(f"{obj}/24", strict=False))
        if obj in ipaddress.ip_network("172.16.0.0/12"):
            return str(ipaddress.ip_network(f"{obj}/24", strict=False))
        if obj in ipaddress.ip_network("192.168.0.0/16"):
            return str(ipaddress.ip_network(f"{obj}/24", strict=False))
        return "Other non-global IPv4"
    else:
        if obj in ipaddress.ip_network("fc00::/7"):
            return "fc00::/7 (ULA)"
        if obj in ipaddress.ip_network("fe80::/10"):
            return "fe80::/10 (link-local)"
        if obj in ipaddress.ip_network("::1/128"):
            return "::1 (loopback)"
        return "Other non-global IPv6"

def public_prefix(ip: str, agg: str = "/16") -> str:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return "INVALID"
    if obj.version == 4:
        o = [int(x) for x in str(obj).split(".")]
        if agg == "/8":
            return f"{o[0]}.0.0.0/8"
        return f"{o[0]}.{o[1]}.0.0/16"
    else:
        hextets = str(obj).split(":")
        hi = hextets[0] if hextets[0] else "0"
        return f"{hi}::/32"

# ------------------- Zabbix API -------------------

class ZabbixAPI:
    def __init__(self, url: str, token: str, timeout: int = DEFAULT_TIMEOUT):
        if not url:
            raise ValueError("Provide --url or ZABBIX_URL env var")
        if not token:
            raise ValueError("Provide --token or ZABBIX_TOKEN env var")
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        })
        self.timeout = timeout
        self._req_id = 0

    def _post(self, payload: dict) -> dict:
        r = self.session.post(self.url, data=json.dumps(payload), timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            err = data["error"]
            raise RuntimeError(f"Zabbix error {err.get('code')}: {err.get('message')} - {err.get('data')}")
        return data["result"]

    def call(self, method: str, params: dict) -> dict:
        self._req_id += 1
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": self._req_id}
        return self._post(payload)

    def host_get_all(self, output=None, select_interfaces=None, select_tags=None,
                     groupids: Optional[List[str]] = None,
                     name_prefix: Optional[str] = None,
                     batch_size: int = DEFAULT_BATCH) -> List[dict]:
        output = output or ["hostid", "host", "name"]
        select_interfaces = select_interfaces or ["ip", "dns", "useip", "type"]
        select_tags = select_tags or ["tag", "value"]
        start = 0
        results: List[dict] = []
        while True:
            params = {
                "output": output,
                "selectInterfaces": select_interfaces,
                "selectTags": select_tags,
                "sortfield": "name",
                "sortorder": "ASC",
                "limit": batch_size,
                "start": start
            }
            if groupids:
                params["groupids"] = groupids
            if name_prefix:
                params["search"] = {"name": name_prefix}
                params["startSearch"] = True
            chunk = self.call("host.get", params)
            if not chunk:
                break
            results.extend(chunk)
            if len(chunk) < batch_size:
                break
            start += batch_size
        return results

    def host_update_tags(self, hostid: str, tags: List[dict]) -> None:
        self.call("host.update", {"hostid": hostid, "tags": tags})

# ------------------- ASN resolver -------------------

class ASNResolverLocalTSV:
    def __init__(self, tsv_path: str):
        self.starts_v4: List[int] = []
        self.ranges_v4: List[Tuple[int, int, str]] = []
        self.starts_v6: List[int] = []
        self.ranges_v6: List[Tuple[int, int, str]] = []
        self._load(tsv_path)

    def _load(self, path: str):
        import gzip
        opener = open
        if path.endswith(".gz"):
            opener = gzip.open

        def add_range(start_ip, end_ip, asn_str, provider):
            try:
                start_obj = ipaddress.ip_address(start_ip)
                end_obj = ipaddress.ip_address(end_ip)
            except ValueError:
                return
            try:
                asn = int(asn_str)
            except ValueError:
                return
            if asn <= 0:
                return
            start_int = int(start_obj)
            end_int = int(end_obj)
            if start_obj.version == 4:
                self.starts_v4.append(start_int)
                self.ranges_v4.append((end_int, asn, provider))
            else:
                self.starts_v6.append(start_int)
                self.ranges_v6.append((end_int, asn, provider))

        with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line or line.startswith("#"):
                    continue
                parts = line.strip().split("\t")
                if len(parts) < 5:
                    continue
                start_ip, end_ip, asn, _, provider = parts[:5]
                add_range(start_ip, end_ip, asn, provider)

        def sort_parallel(starts, ranges):
            combined = sorted(zip(starts, ranges), key=lambda x: x[0])
            starts[:] = [s for s, _ in combined]
            ranges[:] = [r for _, r in combined]

        sort_parallel(self.starts_v4, self.ranges_v4)
        sort_parallel(self.starts_v6, self.ranges_v6)

    def get_asn(self, ip: str) -> Optional[Tuple[str, str]]:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None
        ip_int = int(ip_obj)
        if ip_obj.version == 4:
            idx = bisect.bisect_right(self.starts_v4, ip_int) - 1
            if idx >= 0:
                end_int, asn, provider = self.ranges_v4[idx]
                if ip_int <= end_int:
                    return f"AS{asn}", provider
        else:
            idx = bisect.bisect_right(self.starts_v6, ip_int) - 1
            if idx >= 0:
                end_int, asn, provider = self.ranges_v6[idx]
                if ip_int <= end_int:
                    return f"AS{asn}", provider
        return None

# ------------------- main -------------------

def main():
    parser = argparse.ArgumentParser(description="Zabbix ASN Tools (zbx-asn)")
    parser.add_argument("--url", default=DEFAULT_ZABBIX_URL, help="Zabbix API URL (or ZABBIX_URL env)")
    parser.add_argument("--token", default=os.getenv("ZABBIX_TOKEN"), help="Zabbix API token (or ZABBIX_TOKEN env)")
    parser.add_argument("--ip2asn-tsv", default=DEFAULT_IP2ASN_TSV, help="Path to ip2asn-combined.tsv[.gz]")
    parser.add_argument("--tag-key-asn", default=DEFAULT_TAG_KEY_ASN)
    parser.add_argument("--tag-key-name", default=DEFAULT_TAG_KEY_NAME)
    parser.add_argument("--groupid", action="append")
    parser.add_argument("--name-prefix")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--only-missing", action="store_true")
    parser.add_argument("--clear", action="store_true")
    parser.add_argument("--stats-only", action="store_true")
    parser.add_argument("--top-n", type=int, default=15)
    parser.add_argument("--public-agg", choices=["/16", "/8"], default="/16")
    args = parser.parse_args()

    if not args.url or not args.token:
        print("ERROR: provide --url and --token (or env vars)", file=sys.stderr)
        sys.exit(2)

    zbx = ZabbixAPI(url=args.url, token=args.token, timeout=args.timeout)
    hosts = zbx.host_get_all(
        output=["hostid", "host", "name"],
        select_interfaces=["ip", "dns", "useip", "type"],
        select_tags=["tag", "value"],
        groupids=args.groupid,
        name_prefix=args.name_prefix,
        batch_size=args.batch,
    )
    print(f"Hosts: {len(hosts)}")

    asn_host_counter = Counter()
    class_ip_counter = Counter()
    public_prefix_counter = Counter()
    private_range_counter = Counter()

    if args.clear:
        for h in hosts:
            hostid, name, tags = h["hostid"], h["name"], h.get("tags") or []
            new_tags = [t for t in tags if t.get("tag") not in (args.tag_key_asn, args.tag_key_name)]
            if args.dry_run or args.stats_only:
                print(f"[{hostid}] {name}: DRY-RUN remove {args.tag_key_asn}/{args.tag_key_name}")
            else:
                zbx.host_update_tags(hostid, new_tags)
                print(f"[{hostid}] {name}: removed {args.tag_key_asn}/{args.tag_key_name}")
        return

    print(f"Loading ASN DB: {args.ip2asn_tsv}")
    try:
        resolver = ASNResolverLocalTSV(args.ip2asn_tsv)
    except FileNotFoundError:
        print("ASN DB not found. Download from https://iptoasn.com/data/ip2asn-combined.tsv.gz")
        sys.exit(2)

    updated, skipped = 0, 0

    for h in hosts:
        hostid, name = h["hostid"], h["name"]
        tags = h.get("tags") or []
        ips = collect_host_ips(h)
        pub_ips = [ip for ip in ips if is_public_ip(ip)]
        priv_ips = [ip for ip in ips if not is_public_ip(ip)]

        if not pub_ips and not priv_ips:
            print(f"[{hostid}] {name}: no valid IPs -> skip")
            skipped += 1
            continue

        for ip in pub_ips:
            class_ip_counter[ip_class(ip)] += 1
            public_prefix_counter[public_prefix(ip, args.public_agg)] += 1
        for ip in priv_ips:
            private_range_counter[private_range(ip)] += 1

        asns, names = set(), set()
        for ip in pub_ips:
            res = resolver.get_asn(ip)
            if res:
                asn, provider = res
                asns.add(asn)
                if provider:
                    names.add(provider)
        for asn in asns:
            asn_host_counter[asn] += 1

        if args.stats_only:
            print(f"[{hostid}] {name}: ASNs={', '.join(sorted(asns)) or 'None'}")
            continue

        if not pub_ips:
            skipped += 1
            continue
        if args.only_missing and any(t.get("tag") in (args.tag_key_asn, args.tag_key_name) for t in tags):
            skipped += 1
            continue
        if not asns:
            skipped += 1
            continue

        as_value = ", ".join(sorted(asns))
        name_value = ", ".join(sorted(names))
        cur_as_value = _tags_get_value(tags, args.tag_key_asn)
        cur_name_value = _tags_get_value(tags, args.tag_key_name)
        changed_as = _norm_list_str(as_value) != _norm_list_str(cur_as_value)
        changed_name = _norm_list_str(name_value) != _norm_list_str(cur_name_value)

        if not (changed_as or changed_name):
            skipped += 1
            continue

        new_tags = tags
        if changed_as:
            new_tags = merge_tags(new_tags, args.tag_key_asn, as_value)
        if changed_name:
            new_tags = merge_tags(new_tags, args.tag_key_name, name_value)

        if args.dry_run:
            print(f"[{hostid}] {name}: DRY-RUN update")
        else:
            zbx.host_update_tags(hostid, new_tags)
            print(f"[{hostid}] {name}: updated ASN/ASN_NAME")
            updated += 1

    # Print stats
    total_hosts_with_asn = sum(asn_host_counter.values())
    print("\n=== Top ASNs ===")
    for asn, cnt in asn_host_counter.most_common(args.top_n):
        pct = (cnt / total_hosts_with_asn) * 100 if total_hosts_with_asn else 0
        print(f"{asn:<12} {cnt:>6} {pct:5.1f}%")

    print("\n=== Public IP classes ===")
    for cls in ["A", "B", "C", "D", "E", "IPv6"]:
        cnt = class_ip_counter.get(cls, 0)
        pct = (cnt / sum(class_ip_counter.values())) * 100 if class_ip_counter else 0
        print(f"{cls:<6} {cnt:>6} {pct:5.1f}%")

    print("\n=== Aggregated public prefixes ===")
    for pfx, cnt in public_prefix_counter.most_common(15):
        print(f"{pfx:<18} {cnt:>6}")

    print("\n=== Private/special ranges ===")
    for rng, cnt in private_range_counter.most_common():
        print(f"{rng:<28} {cnt:>6}")

    print(f"\nSummary: updated={updated}, skipped={skipped}, total={len(hosts)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
