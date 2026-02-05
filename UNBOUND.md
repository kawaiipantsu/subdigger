# Running Your Own DNS Resolver with Unbound

For optimal SubDigger performance, running your own local DNS resolver can provide **up to 10x faster** subdomain discovery compared to using public DNS servers. This guide shows you how to set up a minimal Unbound DNS resolver.

## Why Use Your Own DNS Resolver?

**Performance Benefits:**
- **Zero network latency**: Resolver runs on localhost (127.0.0.1)
- **No rate limiting**: Public DNS servers (Google, Cloudflare) rate limit queries
- **Maximum throughput**: Handle thousands of queries per second without throttling
- **No DNS server failures**: Eliminates external DNS server downtime
- **Direct root zone queries**: Unbound queries authoritative nameservers directly

**Real-World Impact:**
- Public DNS (8.8.8.8): ~100-200 queries/second before rate limiting
- Local Unbound: ~2000-5000 queries/second sustained
- **Result**: 10-25x performance improvement on large scans

## Quick Installation

### Debian/Ubuntu

```bash
# Install Unbound
sudo apt-get update
sudo apt-get install -y unbound

# Backup original config
sudo cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.backup

# Create minimal configuration
sudo tee /etc/unbound/unbound.conf > /dev/null <<'EOF'
server:
    # Network interface to listen on
    interface: 0.0.0.0
    interface: ::0

    # Port to listen on
    port: 53

    # Allow queries from anywhere (use with caution on public networks)
    access-control: 0.0.0.0/0 allow
    access-control: ::0/0 allow

    # Performance tuning
    num-threads: 4
    msg-cache-size: 50m
    rrset-cache-size: 100m
    cache-min-ttl: 300
    cache-max-ttl: 86400

    # Reduce latency
    prefetch: yes
    prefetch-key: yes

    # Security
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes

    # Don't be verbose
    verbosity: 1

    # Disable DoT/DoH (we're using UDP for speed)
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes

# Root hints (optional but recommended)
# Download with: sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache
# Uncomment if you downloaded root hints:
# server:
#     root-hints: "/var/lib/unbound/root.hints"
EOF

# Download root hints (optional but recommended for best performance)
sudo mkdir -p /var/lib/unbound
sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache

# Enable root hints in config if downloaded
if [ -f /var/lib/unbound/root.hints ]; then
    echo -e "\nserver:\n    root-hints: \"/var/lib/unbound/root.hints\"" | sudo tee -a /etc/unbound/unbound.conf
fi

# Restart Unbound
sudo systemctl restart unbound
sudo systemctl enable unbound

# Verify it's running
sudo systemctl status unbound
```

### RHEL/CentOS/Rocky

```bash
# Install Unbound
sudo dnf install -y unbound

# Create minimal configuration (same as above)
sudo tee /etc/unbound/unbound.conf > /dev/null <<'EOF'
[Same configuration as Debian above]
EOF

# Download root hints
sudo mkdir -p /var/lib/unbound
sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache

# Start and enable
sudo systemctl restart unbound
sudo systemctl enable unbound
```

## Verify Installation

Test that Unbound is responding to queries:

```bash
# Test with dig
dig @127.0.0.1 google.com

# Test with host
host google.com 127.0.0.1

# Check if it's listening on all interfaces
sudo ss -tulpn | grep unbound
```

Expected output should show Unbound listening on port 53:
```
udp   UNCONN 0  0  0.0.0.0:53     0.0.0.0:*    users:(("unbound",pid=1234,fd=3))
tcp   LISTEN 0  5  0.0.0.0:53     0.0.0.0:*    users:(("unbound",pid=1234,fd=4))
```

## Configure SubDigger to Use Unbound

### Method 1: Edit Configuration File

Edit `~/.subdigger/config`:

```ini
[dns]
servers = 127.0.0.1
```

With local Unbound, you only need **one DNS server** since it's running locally with zero latency.

### Method 2: Command Line (for testing)

While SubDigger doesn't have a command-line DNS server option, you can temporarily edit the config:

```bash
# Backup your config
cp ~/.subdigger/config ~/.subdigger/config.backup

# Update DNS server
sed -i 's/^servers = .*/servers = 127.0.0.1/' ~/.subdigger/config

# Run SubDigger
subdigger -d example.com

# Restore original config if needed
mv ~/.subdigger/config.backup ~/.subdigger/config
```

## Recommended SubDigger Settings for Unbound

When using local Unbound, adjust SubDigger's threading:

```ini
[general]
# Use more threads since there's no network latency
threads = 50

# Reduce timeout since local resolver is fast
timeout = 1

[dns]
# Only need one server - localhost
servers = 127.0.0.1
```

**Thread Recommendations:**
- **With Unbound**: 50-100 threads for optimal performance
- **With public DNS**: 140-200 threads to compensate for latency

## Security Considerations

⚠️ **Warning**: The configuration above allows queries from any IP address (`0.0.0.0/0 allow`). This is suitable for:
- Local development machines
- Internal lab networks
- Dedicated pentest boxes

**For production or multi-user systems**, restrict access to specific networks:

```conf
server:
    # Only allow localhost
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow
    access-control: 0.0.0.0/0 refuse

    # Or allow specific network
    access-control: 192.168.1.0/24 allow
    access-control: 10.0.0.0/8 allow
```

## Firewall Configuration

If you want to allow other machines to use your Unbound resolver:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 53/udp
sudo ufw allow 53/tcp

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-service=dns
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
```

## Performance Tuning for Heavy Loads

For extremely large wordlists (1M+ entries), tune Unbound further:

```conf
server:
    # Increase threads
    num-threads: 8

    # Increase cache sizes
    msg-cache-size: 256m
    rrset-cache-size: 512m

    # More aggressive prefetching
    prefetch: yes
    prefetch-key: yes

    # Increase file descriptors
    outgoing-range: 8192

    # More outgoing ports
    outgoing-num-tcp: 1024
    outgoing-num-udp: 1024

    # Faster response with lower TTL
    cache-min-ttl: 60
    cache-max-ttl: 3600
```

After changes, restart Unbound:
```bash
sudo systemctl restart unbound
```

## Monitoring Performance

Check Unbound statistics:

```bash
# View statistics
sudo unbound-control stats

# View cache stats
sudo unbound-control stats_noreset | grep -E "total.num|total.requestlist"

# Real-time monitoring
watch -n 1 'sudo unbound-control stats_noreset | grep -E "total.num|total.requestlist"'
```

## Troubleshooting

### Unbound Won't Start

```bash
# Check config syntax
sudo unbound-checkconf

# Check logs
sudo journalctl -u unbound -f

# Common issue: Port 53 already in use
sudo ss -tulpn | grep :53
# If systemd-resolved is using port 53, disable it:
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
```

### systemd-resolved Conflicts

On Ubuntu 18.04+, systemd-resolved uses port 53:

```bash
# Disable systemd-resolved
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved

# Remove symlink and create real resolv.conf
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

# Restart Unbound
sudo systemctl restart unbound
```

### Testing Query Performance

Benchmark your Unbound resolver:

```bash
# Install dnsperf
sudo apt-get install dnsperf

# Create test query file
cat > queries.txt <<EOF
google.com A
facebook.com A
amazon.com A
microsoft.com A
EOF

# Run benchmark
dnsperf -s 127.0.0.1 -d queries.txt

# Compare with public DNS
dnsperf -s 8.8.8.8 -d queries.txt
```

## Expected Performance Improvements

**Before (Public DNS - 8.8.8.8):**
```
Scan: 350,000 subdomains
Time: 45-60 minutes
Rate: ~130 queries/second
```

**After (Local Unbound):**
```
Scan: 350,000 subdomains
Time: 5-8 minutes
Rate: ~1200 queries/second
```

**Performance Gain: ~10x faster**

## Alternative: BIND9

If you prefer BIND9 over Unbound:

```bash
sudo apt-get install bind9

# Edit /etc/bind/named.conf.options
sudo nano /etc/bind/named.conf.options
```

Add minimal recursive configuration:
```conf
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
    listen-on { any; };
    listen-on-v6 { any; };
};
```

```bash
sudo systemctl restart bind9
```

However, **Unbound is recommended** for SubDigger due to:
- Lower memory footprint
- Better performance for recursive queries
- Simpler configuration
- Built-in DNSSEC validation

## Resources

- [Unbound Documentation](https://nlnetlabs.nl/documentation/unbound/)
- [Root Hints File](https://www.internic.net/domain/named.cache)
- [DNS Performance Testing](https://github.com/DNS-OARC/dnsperf)

## Support

For issues with Unbound setup, consult:
- Unbound mailing list: unbound-users@nlnetlabs.nl
- SubDigger issues: https://github.com/kawaiipantsu/subdigger/issues
