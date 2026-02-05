# SubDigger

High-performance, multi-threaded subdomain discovery tool for Debian Linux.

## Features

- **Multiple Discovery Methods**: Certificate Transparency, Wordlists, OSINT APIs, Bruteforce, DNS Zone Transfer
- **Comprehensive DNS Enrichment**: A, AAAA, CNAME (with chain following), NS, MX, TXT, CAA, PTR records
- **Dangling DNS Detection**: Identifies subdomain takeover vulnerabilities (CNAME/NS pointing to non-existent domains)
- **GeoIP Integration**: Country, city, and ASN resolution using MaxMind GeoLite2
- **TLD Intelligence**: IANA TLD database with country and manager information
- **Flexible Output**: CSV and JSON formats with real-time streaming
- **High Performance**: Multi-threaded architecture (140 threads default across 7 DNS servers)
- **Smart Caching**: File-based cache with automatic deduplication
- **Recursive Discovery**: Automatically discovers subdomains from CNAME, NS, and ReverseDNS records
- **Health Monitoring**: Per-DNS server statistics with automatic failover
- **Secure**: Input validation, sanitization, and safe coding practices

## Installation

> **💡 Performance Tip:** For optimal speed (10x faster), set up your own DNS resolver before using SubDigger. See [UNBOUND.md](UNBOUND.md) for a quick 5-minute setup guide.

### From Source

```bash
# Install dependencies
apt-get install -y build-essential libc-ares-dev libcurl4-openssl-dev \
                   libjson-c-dev libmaxminddb-dev ruby-ronn

# Build
make

# Install
sudo make install

# Build Debian package
make deb
sudo dpkg -i ../subdigger_1.4.0-1_amd64.deb
```

### Post-Installation

Install GeoIP database for country resolution:

```bash
apt-get install geoipupdate
# Configure /etc/GeoIP.conf with your MaxMind account
geoipupdate
```

## Usage

### Basic Usage

```bash
subdigger -d example.com
```

### Advanced Usage

```bash
# JSON output with real-time streaming
subdigger -d example.com -f json -o results.json

# Enable bruteforce method with depth 4
subdigger -d example.com -m wordlist,cert,bruteforce --bruteforce-depth 4

# Custom wordlist (disables auto-discovery)
subdigger -d example.com -w /path/to/custom-wordlist.txt

# Quiet mode for piping to other tools
subdigger -d example.com -q | grep -i admin

# Disable caching for fresh results
subdigger -d example.com --no-cache

# High-performance scan with all methods
subdigger -d example.com -m wordlist,cert,bruteforce,dns,api -t 280
```

## Configuration

Configuration file: `~/.subdigger/config`

```ini
[general]
# threads = 140  # Auto: 20 per DNS server (default)
timeout = 2

[dns]
servers = 8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,208.67.222.222,208.67.220.220,9.9.9.9

[discovery]
methods = wordlist,cert
wordlist_path = ~/.subdigger/wordlists/common-subdomains.txt
auto_wordlists = true
bruteforce_depth = 3

[output]
format = csv

[cache]
enabled = true

[apis]
# Passive subdomain discovery API keys
# Free tier available: BufferOver (no key required)
bevigil_key =
binaryedge_key =
c99_key =
censys_id =
censys_secret =
certspotter_key =
chaos_key =
fullhunt_key =
github_token =
hunter_key =
intelx_key =
leakix_key =
netlas_key =
passivetotal_user =
passivetotal_key =
securitytrails_key =
shodan_key =
virustotal_key =
whoisxmlapi_key =
zoomeye_key =
```

## Discovery Methods

- **wordlist**: Enumerate subdomains using wordlist files (14 included, auto-discovery enabled)
- **cert**: Query certificate transparency logs via crt.sh
- **bruteforce**: Generate and test subdomain permutations (a-z, 0-9, underscore, depth 1-5)
- **dns**: Attempt DNS zone transfer (AXFR)
- **api**: Query OSINT APIs (19 sources: BeVigil, BinaryEdge, BufferOver, C99, Censys, CertSpotter, Chaos, FullHunt, GitHub, Hunter, IntelX, LeakIX, Netlas, PassiveTotal, SecurityTrails, Shodan, VirusTotal, WhoisXMLAPI, ZoomEye) - most require API keys in config file
- **recursive**: Automatically discovers subdomains from CNAME, NS, and ReverseDNS targets

## API Services

SubDigger supports 19 passive subdomain discovery APIs. Configure API keys in `~/.subdigger/config` under the `[apis]` section.

### Free Tier Services (No API Key Required)
- **BufferOver** - Free passive DNS replication service

### API Key Required

| Service | Get API Key | Notes |
|---------|-------------|-------|
| **BeVigil** | https://bevigil.com/osint-api | Mobile app security platform |
| **BinaryEdge** | https://www.binaryedge.io/ | Internet scanning platform |
| **C99.nl** | https://api.c99.nl/ | Multi-purpose API service |
| **Censys** | https://search.censys.io/api | Requires both `censys_id` and `censys_secret` |
| **CertSpotter** | https://sslmate.com/certspotter/api/ | Certificate transparency monitoring |
| **Chaos** | https://chaos.projectdiscovery.io/ | ProjectDiscovery's subdomain dataset |
| **FullHunt** | https://fullhunt.io/ | Attack surface management |
| **GitHub** | https://github.com/settings/tokens | Code search for subdomains |
| **Hunter** | https://hunter.io/api | Email and domain intelligence |
| **IntelX** | https://intelx.io/ | Intelligence data search engine |
| **LeakIX** | https://leakix.net/ | Internet-wide asset discovery |
| **Netlas** | https://netlas.io/ | Internet assets search |
| **PassiveTotal** | https://community.riskiq.com/ | Requires both `passivetotal_user` and `passivetotal_key` |
| **SecurityTrails** | https://securitytrails.com/ | DNS and domain intelligence |
| **Shodan** | https://account.shodan.io/ | Internet device search engine |
| **VirusTotal** | https://www.virustotal.com/gui/my-apikey | URL and file analysis |
| **WhoisXMLAPI** | https://whoisxmlapi.com/ | Domain and IP intelligence |
| **ZoomEye** | https://www.zoomeye.org/ | Cyberspace search engine |

**Usage:** Add API keys to your config file and use `--methods api` or enable the `api` method in the config.

```bash
# Query all configured APIs
subdigger -d example.com -m api

# Combine with other methods
subdigger -d example.com -m wordlist,cert,api
```

## Output Formats

### CSV (Default)

```csv
Date,Domain,Subdomain,A,AAAA,ReverseDNS,CNAME,CNAME-IP,NS,MX,CAA,TXT,Dangling,TLD,TLD-ISO,TLD-Country,TLD-Type,TLD-Manager,IP-ISO,IP-Country,IP-City,ASN-Org,Source
2026-02-05T14:23:45Z,example.com,www.example.com,93.184.216.34,,,,,ns1.example.com,,,false,false,com,US,United States,generic,IANA,US,United States,Los Angeles,Example AS,wordlist:common
```

### JSON

```json
{
  "subdomains": [
    {
      "timestamp": "2026-02-05T14:23:45Z",
      "domain": "example.com",
      "subdomain": "www.example.com",
      "a_record": "93.184.216.34",
      "aaaa_record": "",
      "reverse_dns": "",
      "cname_record": "",
      "cname_ip": "",
      "ns_record": "ns1.example.com",
      "mx_record": "",
      "caa": false,
      "txt": false,
      "dangling": false,
      "tld": "com",
      "tld_iso": "US",
      "tld_country": "United States",
      "tld_type": "generic",
      "tld_manager": "IANA",
      "ip_iso": "US",
      "ip_country": "United States",
      "ip_city": "Los Angeles",
      "asn_org": "Example AS",
      "source": "wordlist:common"
    }
  ]
}
```

## Performance

- **140 default threads** (20 per DNS server across 7 servers)
- **Up to 1400 threads** maximum (200 per DNS server)
- **Real-time streaming output** - no waiting for scan completion
- Asynchronous DNS resolution with c-ares (per-thread DNS channels)
- Thread-safe task queue and result buffer with mutex protection
- Automatic deduplication and result caching
- Per-DNS server health monitoring and automatic failover
- 3-second timeout protection with thread respawning

### ⚡ Optimal Performance: Run Your Own DNS Resolver

**For 10x faster performance**, run your own local DNS resolver instead of using public DNS servers.

**Performance Comparison:**
- Public DNS (8.8.8.8): ~130 queries/second (rate limited)
- Local Unbound: ~1200+ queries/second (no limits)

**Why it's faster:**
- Zero network latency (localhost)
- No rate limiting from public DNS providers
- Direct queries to authoritative nameservers
- Maximum thread utilization

**Setup Guide:** See [UNBOUND.md](UNBOUND.md) for a complete installation and configuration guide for running your own Unbound DNS resolver.

**Quick setup:**
```bash
# Install Unbound
sudo apt-get install unbound

# Configure SubDigger to use it
echo "servers = 127.0.0.1" >> ~/.subdigger/config
```

With local DNS, a 350k subdomain scan takes **5-8 minutes** instead of 45-60 minutes!

## Security

- Domain validation (RFC 1035 compliance)
- Input sanitization (alphanumeric + dots + hyphens)
- Path traversal prevention
- Configuration file permission checks
- Stack protection and buffer overflow defenses
- No global mutable state without synchronization

## Dependencies

- libc-ares2: Asynchronous DNS resolution
- libcurl4: HTTP client for API queries
- libjson-c5: JSON parsing
- libmaxminddb0: GeoIP database lookups
- geoipupdate: GeoIP database updater (recommended)

## Contributing

Contributions are welcome! Please see [GITHUB_INFO.md](GITHUB_INFO.md) for guidelines.

## Issues and Bug Reports

Report issues at: https://github.com/kawaiipantsu/subdigger/issues

## License

MIT License

## Author

Developed by Kawaiipantsu (thugsred@protonmail.com) for security research and penetration testing.

## Repository

GitHub: https://github.com/kawaiipantsu/subdigger
