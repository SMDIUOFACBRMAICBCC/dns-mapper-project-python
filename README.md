# DNS Mapper

DNS environment mapping tool that discovers all IP addresses and domain names associated with a given domain using only DNS queries.

## Installation

```bash
pip install -r requirements.txt
```

You also need Graphviz installed on your system:
- Windows: `choco install graphviz` or download from https://graphviz.org/download/
- Linux: `sudo apt install graphviz`
- macOS: `brew install graphviz`

## Usage

```bash
# Basic usage
python -m dns_mapper example.com

# With options
python -m dns_mapper example.com -d 2 -f png -o graph.png

# Text output only
python -m dns_mapper example.com -f text

# Generate SVG graph
python -m dns_mapper example.com -f svg -o graph.svg
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --depth` | Recursion depth | 2 |
| `-o, --output` | Output file | stdout/graph.png |
| `-f, --format` | Output format: text, dot, png, svg | text |
| `-s, --strategies` | Strategies to use (comma-separated) | all |

## Strategies

1. **parse_txt** - Parse TXT records for IPs and domains
2. **crawl_tld** - Discover parent domains up to TLD
3. **scan_srv** - Scan SRV records for services
4. **reverse_dns** - Reverse DNS lookup (PTR records)
5. **ip_neighbors** - Scan neighboring IP addresses
6. **subdomain** - Enumerate common subdomains

## Example Output

```
$ python -m dns_mapper se.com -d 1 -f text

=== DNS Mapper Report for se.com ===

Domains discovered:
  - se.com (A: 34.227.236.7)
  - www.se.com (CNAME: se.com)
  - mail.se.com (A: 185.132.182.5)
  ...

IP addresses discovered:
  - 34.227.236.7 (PTR: ec2-34-227-236-7.compute-1.amazonaws.com)
  ...
```

## Author

Created for Python B1 course at OTERIA 2025-2026
