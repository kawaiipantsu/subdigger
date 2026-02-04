#!/bin/bash
#
# SubDigger - Initial Git Setup Script
# Run this script to prepare the initial commit
#

echo "=========================================="
echo "  SubDigger - Git Initialization"
echo "=========================================="
echo ""

# Check if we're already in a git repo
if [ -d .git ]; then
    echo "✓ Git repository already initialized"
else
    echo "→ Initializing git repository..."
    git init
fi

echo ""
echo "→ Adding all files to staging..."
git add .

echo ""
echo "→ Current status:"
git status --short

echo ""
echo "=========================================="
echo "Ready to commit!"
echo "=========================================="
echo ""
echo "Next commands:"
echo ""
echo "  1. Commit:"
echo "     git commit -m \"Initial release of SubDigger v1.0.0"
echo ""
echo "     High-performance subdomain discovery tool for Debian Linux."
echo "     Features multi-threaded DNS, CT logs, OSINT APIs, and GeoIP.\""
echo ""
echo "  2. Add remote:"
echo "     git remote add origin git@github.com:kawaiipantsu/subdigger.git"
echo ""
echo "  3. Push:"
echo "     git branch -M main"
echo "     git push -u origin main"
echo ""
echo "=========================================="
