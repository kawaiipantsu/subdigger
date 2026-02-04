# GitHub Repository Information

## Repository URL
```
https://github.com/kawaiipantsu/subdigger
```

## Short Description (max 350 characters for GitHub)

**Option 1 (Concise):**
```
High-performance subdomain discovery tool written in C for Debian Linux. Features multi-threaded DNS resolution, certificate transparency, wordlist enumeration, OSINT API integration, and GeoIP support. Outputs CSV/JSON with full DNS record enrichment.
```

**Option 2 (Feature-focused):**
```
Multi-threaded subdomain enumeration tool with certificate transparency, wordlist scanning, bruteforce generation, and OSINT APIs (Shodan/VirusTotal). Async DNS resolution using c-ares, GeoIP integration, and CSV/JSON output. Built for security researchers.
```

**Option 3 (Technical):**
```
C-based subdomain discovery CLI with asynchronous DNS (c-ares), CT log integration, OSINT APIs, and multi-threaded architecture. Discovers subdomains via wordlists, certificates, bruteforce, and zone transfers. Debian-native with comprehensive DNS enrichment.
```

**Recommended (Balanced):**
```
Fast, multi-threaded subdomain discovery tool for security professionals. Leverages certificate transparency, wordlists, OSINT APIs, and intelligent bruteforce. Written in C with async DNS resolution and GeoIP support. Outputs enriched results in CSV/JSON.
```

## GitHub Topics/Tags

### Essential Tags (Primary)
```
subdomain-enumeration
subdomain-scanner
dns-enumeration
security-tools
penetration-testing
reconnaissance
osint
```

### Technical Tags
```
c
multi-threaded
async-dns
certificate-transparency
debian
linux-tools
```

### Feature Tags
```
geoip
wordlist
bruteforce
api-integration
dns-resolution
threat-intelligence
```

### Use Case Tags
```
bug-bounty
red-team
security-research
vulnerability-assessment
infosec
cybersecurity
```

### Suggested Tag Combination (max 20 tags)
```
subdomain-enumeration
subdomain-scanner
dns-enumeration
security-tools
penetration-testing
osint
reconnaissance
c
certificate-transparency
multi-threaded
geoip
debian
bug-bounty
infosec
cybersecurity
wordlist
api-integration
red-team
dns-resolution
threat-intelligence
```

## README Badge Suggestions

Add these to the top of README.md:

```markdown
# SubDigger

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/kawaiipantsu/subdigger/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Debian%20Linux-red.svg)](https://www.debian.org/)
[![Language](https://img.shields.io/badge/language-C-orange.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
```

## Social Media Descriptions

### Twitter/X Post
```
🚀 Just released SubDigger v1.0.0 - a high-performance subdomain discovery tool written in C!

✅ Multi-threaded DNS resolution
✅ Certificate Transparency
✅ OSINT API integration
✅ GeoIP support
✅ CSV/JSON output

Perfect for bug bounty hunters & security researchers!

https://github.com/kawaiipantsu/subdigger

#bugbounty #infosec #pentesting #osint
```

### LinkedIn Post
```
Excited to share SubDigger v1.0.0 - a professional-grade subdomain enumeration tool for security professionals.

Key capabilities:
• Asynchronous multi-threaded DNS resolution (c-ares)
• Certificate Transparency log integration
• OSINT API support (Shodan, VirusTotal)
• GeoIP country resolution
• Wordlist and intelligent bruteforce enumeration
• Enterprise-ready output (CSV/JSON)

Built with security and performance in mind - secure coding practices, input validation, and optimized for 1000+ DNS queries/second.

Open source and available on GitHub.

#CyberSecurity #InfoSec #PenetrationTesting #BugBounty #OSINT
```

### Reddit r/netsec Post Title
```
[Tool Release] SubDigger v1.0.0 - High-Performance Subdomain Discovery in C
```

### Reddit Post Body
```
Hi r/netsec,

I've just released SubDigger v1.0.0, a subdomain enumeration tool designed for security researchers and penetration testers.

**What makes it different:**
- Written in pure C with async DNS (c-ares) for performance
- Multi-method approach: CT logs, wordlists, OSINT APIs, bruteforce
- Thread-safe architecture (1-200 configurable threads)
- Comprehensive DNS enrichment (A, AAAA, CNAME, NS, MX, TXT)
- GeoIP integration for threat intelligence
- 24-hour result caching to avoid redundant scans

**Performance:**
Target: 1000+ DNS queries/second with 50 threads
Binary size: 56KB (optimized)
Security: Stack protection, input validation, safe string operations

**Perfect for:**
- Bug bounty reconnaissance
- Red team operations
- Security assessments
- OSINT investigations

GitHub: https://github.com/kawaiipantsu/subdigger

Feedback and contributions welcome!
```

## Release Notes Template

### v1.0.0 - Initial Release

**Release Date:** 2026-02-04

**Highlights:**
- Multi-threaded subdomain discovery with configurable thread pool (1-200 threads)
- Certificate Transparency integration via crt.sh API
- OSINT API support (Shodan, VirusTotal)
- Wordlist enumeration with 199 curated default subdomains
- Intelligent bruteforce generation (a-z, 0-9, depth 1-3)
- DNS zone transfer attempts (AXFR)
- Asynchronous DNS resolution using c-ares
- Full DNS record enrichment (A, AAAA, CNAME, NS, MX, TXT)
- GeoIP country code resolution (MaxMind GeoLite2)
- CSV and JSON output formats
- 24-hour file-based result caching
- INI-style configuration system
- Secure coding practices (input validation, stack protection)
- Debian package ready

**Technical Details:**
- Language: C
- Lines of Code: 2,447
- Binary Size: 56KB
- Dependencies: libc-ares2, libcurl4, libjson-c5, libmaxminddb0

**Installation:**
```bash
# From source
make
sudo make install

# Using .deb package
make deb
sudo dpkg -i ../subdigger_1.0.0-1_amd64.deb
```

**Basic Usage:**
```bash
subdigger -d example.com
subdigger -d example.com -f json -o results.json
subdigger -d example.com -m wordlist,cert -t 100
```

**Documentation:**
- README.md - User guide
- man subdigger - Man page
- IMPLEMENTATION.md - Technical details

**Security:**
- RFC 1035 domain validation
- Input sanitization
- Path traversal prevention
- Stack protection enabled
- Config permission warnings

## Project Website Content (if creating one)

### Tagline
```
Discover subdomains at lightning speed
```

### Hero Description
```
SubDigger is a professional-grade subdomain enumeration tool built for
security researchers, penetration testers, and bug bounty hunters.
Leveraging multiple discovery methods and asynchronous DNS resolution,
it delivers comprehensive results in seconds.
```

### Feature Highlights

**⚡ High Performance**
Multi-threaded architecture with asynchronous DNS resolution. Target: 1000+ queries/second.

**🔍 Multiple Discovery Methods**
Certificate Transparency, wordlists, OSINT APIs, intelligent bruteforce, and DNS zone transfers.

**🌍 GeoIP Integration**
Automatic country code resolution using MaxMind GeoLite2 for threat intelligence.

**📊 Rich Output**
CSV and JSON formats with full DNS enrichment (A, AAAA, CNAME, NS, MX, TXT records).

**🔒 Security First**
Built with secure coding practices - input validation, stack protection, and safe operations.

**⚙️ Highly Configurable**
INI-style configuration, custom wordlists, API integration, and flexible thread management.

## SEO Keywords

```
subdomain enumeration tool
subdomain scanner
DNS reconnaissance
certificate transparency scanner
subdomain discovery
OSINT tool
bug bounty tools
penetration testing tools
security reconnaissance
domain enumeration
DNS enumeration
subdomain finder
security tools linux
debian security tools
C security tools
multi-threaded subdomain scanner
async DNS resolver
GeoIP subdomain tool
threat intelligence tool
red team tools
```

## GitHub Labels for Issues

Suggested labels for issue management:

```
bug - Something isn't working
enhancement - New feature or request
documentation - Improvements or additions to documentation
security - Security-related issue or improvement
performance - Performance optimization
question - Further information is requested
help-wanted - Extra attention is needed
good-first-issue - Good for newcomers
wontfix - This will not be worked on
duplicate - This issue or pull request already exists
feature-request - Request for new functionality
```

## Contributor Guidelines Snippet

```markdown
## Contributing to SubDigger

We welcome contributions! Here's how you can help:

### Reporting Bugs
- Use GitHub Issues
- Include SubDigger version (`subdigger --version`)
- Provide detailed reproduction steps
- Include relevant logs/output

### Suggesting Features
- Open a GitHub Issue with the `feature-request` label
- Describe the use case
- Explain expected behavior

### Code Contributions
1. Fork the repository
2. Create a feature branch
3. Follow existing code style
4. Test thoroughly
5. Submit a pull request

### Code Standards
- C99 standard
- Compile with `-Wall -Wextra -Werror`
- Use safe string functions (strncpy, snprintf)
- Add comments for complex logic
- Update documentation

### Testing
Run tests before submitting:
```bash
make clean && make test
```

For security tools: test only against domains you own or have permission to scan.
```
