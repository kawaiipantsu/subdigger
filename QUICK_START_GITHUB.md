# SubDigger - GitHub Quick Start Guide

## 📋 Pre-Upload Checklist

✅ **Maintainer Updated**: Kawaiipantsu <thugsred@protonmail.com>
✅ **GitHub URL Set**: https://github.com/kawaiipantsu/subdigger
✅ **.gitignore Created**: Protects binaries and build artifacts
✅ **LICENSE Added**: MIT License
✅ **Documentation Complete**: README, Implementation Guide, Verification Report

---

## 🚀 Step 1: Create GitHub Repository

1. Go to: https://github.com/new
2. Repository name: `subdigger`
3. Description: Copy from below
4. Public repository
5. **DO NOT** initialize with README, .gitignore, or license (already created locally)

### Repository Description (paste in "About" section):
```
Fast, multi-threaded subdomain discovery tool for security professionals. Leverages certificate transparency, wordlists, OSINT APIs, and intelligent bruteforce. Written in C with async DNS resolution and GeoIP support. Outputs enriched results in CSV/JSON.
```

---

## 📦 Step 2: Initial Commit and Push

```bash
cd /var/www/projects/subdigger

# Option A: Use the helper script
./INITIAL_COMMIT.sh

# Then commit
git commit -m "Initial release of SubDigger v1.0.0

High-performance subdomain discovery tool for Debian Linux.
Features multi-threaded DNS, CT logs, OSINT APIs, and GeoIP."

# Option B: Manual setup
git init
git add .
git commit -m "Initial release of SubDigger v1.0.0"

# Add remote and push
git remote add origin git@github.com:kawaiipantsu/subdigger.git
git branch -M main
git push -u origin main
```

---

## 🏷️ Step 3: Add Topics (Tags) to Repository

Go to: https://github.com/kawaiipantsu/subdigger

Click "⚙️ Settings" → Under "About" click "⚙️" (gear icon) → Add these topics:

**Essential (must-have):**
- subdomain-enumeration
- subdomain-scanner
- dns-enumeration
- security-tools
- penetration-testing
- osint
- reconnaissance

**Technical:**
- c
- certificate-transparency
- multi-threaded
- geoip
- debian

**Use Case:**
- bug-bounty
- infosec
- cybersecurity
- red-team

**Additional:**
- wordlist
- api-integration
- dns-resolution
- threat-intelligence

*Total: 20 topics (GitHub maximum)*

---

## 🎯 Step 4: Create First Release

1. Go to: https://github.com/kawaiipantsu/subdigger/releases
2. Click "Create a new release"
3. Click "Choose a tag" → Type `v1.0.0` → "Create new tag: v1.0.0 on publish"
4. Release title: `SubDigger v1.0.0 - Initial Release`
5. Description: Copy from [GITHUB_INFO.md](GITHUB_INFO.md) under "Release Notes Template"
6. Click "Publish release"

### Quick Release Description:

```markdown
## SubDigger v1.0.0 - Initial Release

High-performance, multi-threaded subdomain discovery tool written in C for Debian Linux.

### 🎯 Key Features
- Multi-threaded DNS resolution (c-ares async, 1-200 threads)
- Certificate Transparency integration (crt.sh)
- OSINT APIs (Shodan, VirusTotal)
- Wordlist enumeration (199 default subdomains)
- Intelligent bruteforce (a-z, 0-9, depth 1-3)
- Full DNS enrichment (A, AAAA, CNAME, NS, MX, TXT)
- GeoIP country resolution (MaxMind GeoLite2)
- CSV and JSON output formats
- 24-hour result caching
- Secure coding practices

### 📊 Technical Details
- **Language**: C
- **Lines of Code**: 2,447
- **Binary Size**: 56KB
- **Performance**: 1000+ DNS queries/second
- **Dependencies**: libc-ares2, libcurl4, libjson-c5, libmaxminddb0

### 📥 Installation

**From Source:**
```bash
git clone https://github.com/kawaiipantsu/subdigger.git
cd subdigger
make
sudo make install
```

**Debian Package:**
```bash
make deb
sudo dpkg -i ../subdigger_1.0.0-1_amd64.deb
```

### 🔧 Quick Start
```bash
subdigger -d example.com
subdigger -d example.com -f json -o results.json
subdigger -d example.com -m wordlist,cert -t 100
```

### 📖 Documentation
- [README.md](README.md) - User guide
- [IMPLEMENTATION.md](IMPLEMENTATION.md) - Technical details
- [VERIFICATION.md](VERIFICATION.md) - Test results
- `man subdigger` - Man page

### 🔒 Security
- RFC 1035 domain validation
- Input sanitization and path traversal prevention
- Stack protection and buffer overflow defenses
- Config permission warnings
- No global mutable state without synchronization
```

---

## 🎨 Step 5: Enhance README with Badges (Optional)

Add these badges to the top of README.md:

```markdown
# SubDigger

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/kawaiipantsu/subdigger/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Debian%20Linux-red.svg)](https://www.debian.org/)
[![Language](https://img.shields.io/badge/language-C-orange.svg)](https://en.wikipedia.org/wiki/C_(programming_language))

High-performance, multi-threaded subdomain discovery tool for Debian Linux.
[rest of README...]
```

---

## 📣 Step 6: Share on Social Media (Optional)

### Twitter/X:
```
🚀 Just released SubDigger v1.0.0 - a high-performance subdomain discovery tool written in C!

✅ Multi-threaded DNS resolution
✅ Certificate Transparency
✅ OSINT API integration
✅ GeoIP support
✅ CSV/JSON output

Perfect for bug bounty hunters & security researchers!

https://github.com/kawaiipantsu/subdigger

#bugbounty #infosec #pentesting #osint #cybersecurity
```

### Reddit (r/netsec, r/bugbounty):
**Title:** `[Tool Release] SubDigger v1.0.0 - High-Performance Subdomain Discovery in C`

**Body:** See full post template in [GITHUB_INFO.md](GITHUB_INFO.md)

### LinkedIn:
Professional-focused post template available in [GITHUB_INFO.md](GITHUB_INFO.md)

---

## 🛠️ Step 7: Configure Repository Settings

### Enable Features:
- ✅ Issues
- ✅ Wiki (optional)
- ✅ Discussions (optional for community)

### Branch Protection (optional):
1. Go to Settings → Branches
2. Add rule for `main` branch
3. Require pull request reviews before merging
4. Require status checks to pass

### Labels for Issues:
Create these labels for better organization:
- `bug` (red) - Something isn't working
- `enhancement` (blue) - New feature or request
- `documentation` (green) - Documentation improvements
- `security` (purple) - Security-related
- `performance` (yellow) - Performance optimization
- `question` (gray) - Further information requested
- `good-first-issue` (green) - Good for newcomers
- `help-wanted` (orange) - Extra attention needed

---

## 📝 Files Included in Repository

### Source Code (15 files):
- `src/*.c` - All C source modules (2,315 LOC)
- `include/subdigger.h` - Core definitions (130 LOC)

### Documentation (6 files):
- `README.md` - User guide
- `LICENSE` - MIT License
- `IMPLEMENTATION.md` - Technical implementation details
- `VERIFICATION.md` - Testing and verification report
- `GITHUB_INFO.md` - Detailed GitHub setup guide
- `QUICK_START_GITHUB.md` - This file

### Build System:
- `Makefile` - Build automation
- `debian/*` - Debian packaging files

### Configuration:
- `.gitignore` - Git ignore rules (protects binaries)
- `man/subdigger.1.ronn` - Man page source

### Resources:
- `wordlists/common-subdomains.txt` - Default wordlist (199 entries)

---

## ✅ What's Protected by .gitignore

The `.gitignore` file prevents these from being committed:
- Compiled binary: `subdigger`
- Object files: `*.o`
- Debian build artifacts: `debian/subdigger/`, `*.deb`
- Generated man pages: `man/subdigger.1`
- Editor files: `.vscode/`, `.idea/`, `*.swp`
- Backup files: `*~`, `*.bak`
- Cache and temporary files

---

## 🎯 Expected Repository Structure on GitHub

```
kawaiipantsu/subdigger/
├── src/                    # C source files
├── include/                # Header files
├── man/                    # Man page source
├── debian/                 # Debian packaging
├── wordlists/              # Default wordlist
├── .gitignore              # Git ignore rules
├── LICENSE                 # MIT License
├── Makefile                # Build system
├── README.md               # User documentation
├── IMPLEMENTATION.md       # Technical docs
├── VERIFICATION.md         # Test results
└── GITHUB_INFO.md          # GitHub setup guide
```

---

## 🔐 Security Note

**Important**: The tool is designed for authorized security testing only. Users must:
- Only scan domains they own or have explicit permission to test
- Comply with applicable laws and regulations
- Respect rate limits when using OSINT APIs
- Not use for malicious purposes

Add this to repository description or README if needed.

---

## 📧 Contact & Support

- **Author**: Kawaiipantsu
- **Email**: thugsred@protonmail.com
- **Issues**: https://github.com/kawaiipantsu/subdigger/issues
- **Discussions**: https://github.com/kawaiipantsu/subdigger/discussions (if enabled)

---

## 🚦 Ready to Go!

Your repository is now ready for:
- ✅ Clean commits (no build artifacts)
- ✅ Professional presentation
- ✅ Community contributions
- ✅ Security research use

**Next**: Run `./INITIAL_COMMIT.sh` and follow the prompts!
