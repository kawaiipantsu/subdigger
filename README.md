# SubDigger

High-performance, multi-threaded subdomain discovery tool for Debian Linux.

## Features

- **Multiple Discovery Methods**: Certificate Transparency, Wordlists, OSINT APIs, Bruteforce, DNS Zone Transfer
- **Comprehensive DNS Enrichment**: A, CNAME, NS, MX, TXT records
- **GeoIP Integration**: Resolve IPs to country ISO codes using MaxMind GeoLite2
- **Flexible Output**: CSV and JSON formats
- **High Performance**: Multi-threaded architecture with c-ares async DNS
- **Smart Caching**: 24-hour file-based cache to avoid redundant scans
- **Secure**: Input validation, sanitization, and safe coding practices

## Installation

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
sudo dpkg -i ../subdigger_1.0.0-1_amd64.deb
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
# JSON output
subdigger -d example.com -f json -o results.json

# Specific methods with custom threads
subdigger -d example.com -m wordlist,cert -t 100

# Custom wordlist
subdigger -d example.com -w /usr/share/wordlists/dns.txt

# Disable caching
subdigger -d example.com --no-cache
```

## Configuration

Configuration file: `~/.subdigger/config`

```ini
[general]
threads = 50
timeout = 5

[dns]
servers = 8.8.8.8,1.1.1.1

[discovery]
methods = wordlist,cert,bruteforce
wordlist_path = ~/.subdigger/wordlists/common-subdomains.txt
bruteforce_depth = 2

[output]
format = csv

[cache]
enabled = true

[apis]
shodan_key = YOUR_SHODAN_API_KEY
virustotal_key = YOUR_VIRUSTOTAL_API_KEY
```

## Discovery Methods

- **wordlist**: Enumerate subdomains using a wordlist file
- **cert**: Query certificate transparency logs via crt.sh
- **bruteforce**: Generate and test subdomain permutations (a-z, 0-9)
- **dns**: Attempt DNS zone transfer (AXFR)
- **api**: Query OSINT APIs (Shodan, VirusTotal) if API keys provided

## Output Formats

### CSV (Default)

```csv
Date,Subdomain,A/CNAME,NS,MX,TXT_Present,TLD,Country,Source
2026-02-04T14:23:45Z,www.example.com,93.184.216.34,N/A,N/A,No,com,US,discovery
```

### JSON

```json
{
  "subdomains": [
    {
      "timestamp": "2026-02-04T14:23:45Z",
      "subdomain": "www.example.com",
      "a_record": "93.184.216.34",
      "cname_record": "N/A",
      "ns_record": "N/A",
      "mx_record": "N/A",
      "has_txt": false,
      "tld": "com",
      "country_code": "US",
      "source": "discovery"
    }
  ]
}
```

## Performance

Target: **1000+ DNS queries per second** with 50 threads

- Asynchronous DNS resolution with c-ares
- Thread-safe task queue and result buffer
- Automatic deduplication
- Configurable worker pool (up to 200 threads)

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
