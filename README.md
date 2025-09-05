# Zabbix ASN Tools `zbx-asn`

**Zabbix ASN Tools** helps enrich Zabbix host inventories with network context.  
It maps host IPs to their Autonomous System Numbers (ASN) using a local `ip2asn` database, updates tags automatically, and provides statistics that give administrators better visibility into external connectivity and infrastructure.

---

## Features
- Annotates Zabbix hosts with `ASN` and `ASN_NAME` tags.
- Works with a local [ip2asn.com](https://iptoasn.com) TSV database.
- Provides clear statistics about:
  - ASN distribution across hosts
  - Public IPv4 prefix aggregation (/16 or /8)
  - IPv4 class distribution
  - Private and special ranges (IPv4/IPv6)
- Multiple operating modes:
  - **Dry-run**: preview changes without applying them
  - **Stats-only**: calculate and display statistics
  - **Clear**: remove ASN-related tags
  - **Only-missing**: update only hosts without ASN tags
- Filters by Zabbix group ID or name prefix
- Supports modern Zabbix authentication (Bearer token)

---

## Requirements
- Python 3.8+
- Dependencies:
  ```
  pip install requests
  ```
- Local ASN database:  
  Download the latest TSV (or `.gz`) from  
  [https://iptoasn.com/data/ip2asn-combined.tsv.gz](https://iptoasn.com/data/ip2asn-combined.tsv.gz)

---

## Usage

Export credentials first:

```
export ZABBIX_URL="http://your-zabbix/api_jsonrpc.php"
export ZABBIX_TOKEN="your-api-token"
```

### Dry-run (preview changes)
```
python zbx_asn.py --ip2asn-tsv ip2asn-combined.tsv.gz --dry-run
```

### Apply ASN tags
```
python zbx_asn.py --ip2asn-tsv ip2asn-combined.tsv.gz
```

### Stats only
```
python zbx_asn.py --ip2asn-tsv ip2asn-combined.tsv.gz --stats-only
```

### Clear tags
```
python zbx_asn.py --ip2asn-tsv ip2asn-combined.tsv.gz --clear
```

### Only missing
```
python zbx_asn.py --ip2asn-tsv ip2asn-combined.tsv.gz --only-missing
```

### Filter by group
```
python zbx_asn.py --ip2asn-tsv ip2asn-combined.tsv.gz --groupid 2 --dry-run
```

### Filter by name prefix
```
python zbx_asn.py --ip2asn-tsv ip2asn-combined.tsv.gz --name-prefix web --dry-run
```

### Change prefix aggregation
```
python zbx_asn.py --ip2asn-tsv ip2asn-combined.tsv.gz --public-agg /8 --stats-only
```

---

## Example output

```
Hosts: 42

=== Top ASNs ===
AS12345        10   23.8%
AS67890         7   16.7%
...

=== Public IP classes ===
A         15   50.0%
B          5   16.7%
IPv6      10   33.3%

=== Aggregated public prefixes (/16) ===
192.168.0.0/16      12
203.0.0.0/16        5
...

=== Private/special ranges ===
10.0.0.0/24         8
fc00::/7 (ULA)      3
```

---

## Development

Create a virtual environment:

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.  
See the [LICENSE](LICENSE) file for details.

---

## Credits

- ASN dataset: [iptoasn.com](https://iptoasn.com)
- Built with 🖥️, 🧠 and ❤️ to `enhance` network operations.
