# 🔥 AKUMA Scanner - Usage Examples

## Basic Scanning Examples

### 1. Quick Demo Scan
Test the scanner on a small subset to verify functionality:

```bash
# Run demo version (quick and safe)
./demo_scanner.sh
```

### 2. Basic Network Scan
Scan with default configuration (unauthenticated):

```bash
# Scan default subnet (192.168.112.0/22)
./advanced_lowhanging_scanner.sh
```

### 3. Custom Subnet Scan
Modify the config file and scan specific networks:

```bash
# Edit config file first
nano scanner_config.conf

# Then run scan
./advanced_lowhanging_scanner.sh --config scanner_config.conf
```

## Advanced Scanning Examples

### 4. Authenticated Domain Scan
Full scan with domain credentials:

```bash
./advanced_lowhanging_scanner.sh \
  --auth \
  --username "administrator" \
  --password "P@ssw0rd123!" \
  --domain "CORP" \
  --debug
```

### 5. Quick Vulnerability Test
Test only critical vulnerabilities on discovered hosts:

```bash
# First run discovery
./advanced_lowhanging_scanner.sh

# Then test specific vulnerabilities
./vuln_tester.sh
```

### 6. Multiple Subnet Corporate Scan
```bash
# Create custom config for multiple subnets
cat > corporate_config.conf << EOF
SUBNETS=(
    "10.0.0.0/24"
    "10.1.0.0/24" 
    "192.168.100.0/24"
    "172.16.0.0/24"
)
MAX_PARALLEL=30
TIMEOUT_PER_HOST=180
AUTHENTICATED_SCAN=true
USERNAME="svc-scanner"
PASSWORD="Sc@nn3r2024!"
DOMAIN="CORPORATE"
EOF

# Run the scan
./advanced_lowhanging_scanner.sh --config corporate_config.conf
```

## Specialized Scanning Scenarios

### 7. High-Speed Network Discovery
For large networks, optimize for speed:

```bash
# Create speed-optimized config
cat > speed_config.conf << EOF
SUBNETS=("10.0.0.0/8")
MAX_PARALLEL=50
TIMEOUT_PER_HOST=60
NMAP_THREADS=200
DEBUG_MODE=false
EOF

./advanced_lowhanging_scanner.sh --config speed_config.conf
```

### 8. Stealth Scanning (Slower, Less Detectable)
```bash
# Create stealth config
cat > stealth_config.conf << EOF
SUBNETS=("192.168.1.0/24")
MAX_PARALLEL=5
TIMEOUT_PER_HOST=600
NMAP_THREADS=20
DEBUG_MODE=false
EOF

./advanced_lowhanging_scanner.sh --config stealth_config.conf
```

### 9. Research Environment Testing
Safe testing on isolated lab networks:

```bash
# Lab environment config
cat > lab_config.conf << EOF
SUBNETS=(
    "192.168.100.0/24"  # Windows Domain
    "192.168.101.0/24"  # Linux Servers  
    "192.168.102.0/24"  # DMZ
)
MAX_PARALLEL=20
AUTHENTICATED_SCAN=true
USERNAME="labuser"
PASSWORD="LabTest123"
DOMAIN="LAB"
DEBUG_MODE=true
EOF

./advanced_lowhanging_scanner.sh --config lab_config.conf
```

## Command Line Options Reference

### Basic Options
```bash
# Show help
./advanced_lowhanging_scanner.sh --help

# Enable debug mode
./advanced_lowhanging_scanner.sh --debug

# Use custom config
./advanced_lowhanging_scanner.sh --config /path/to/config.conf
```

### Authentication Options
```bash
# Local authentication
./advanced_lowhanging_scanner.sh \
  --auth \
  --username "admin" \
  --password "password"

# Domain authentication
./advanced_lowhanging_scanner.sh \
  --auth \
  --username "user" \
  --password "pass" \
  --domain "DOMAIN"
```

## Output Analysis Examples

### 10. Analyzing Results
```bash
# View critical vulnerabilities
cat ~/lowhanging_results/scan_*/CRITICAL_VULNERABILITIES.txt

# Check HTML report
firefox ~/lowhanging_results/scan_*/reports/detailed_report.html

# Review discovery statistics
cat ~/lowhanging_results/scan_*/reports/vulnerability_summary.txt
```

### 11. Extracting Specific Data
```bash
# Get all SMB hosts
cat ~/lowhanging_results/scan_*/smb_hosts.txt

# Find all HTTP services  
cat ~/lowhanging_results/scan_*/http_hosts.txt

# List vulnerable systems
grep -r "VULNERABLE" ~/lowhanging_results/scan_*/results/
```

## Real-World Penetration Testing Scenarios

### 12. External Network Assessment
```bash
# External IP ranges (get authorization first!)
cat > external_config.conf << EOF
SUBNETS=(
    "203.0.113.0/24"    # Replace with actual authorized ranges
)
MAX_PARALLEL=10
TIMEOUT_PER_HOST=300
AUTHENTICATED_SCAN=false  # No credentials for external
EOF

./advanced_lowhanging_scanner.sh --config external_config.conf
```

### 13. Internal Network After Initial Compromise
```bash
# After gaining initial foothold with credentials
./advanced_lowhanging_scanner.sh \
  --auth \
  --username "compromised-user" \
  --password "found-password" \
  --domain "TARGET-DOMAIN" \
  --debug > pentest_session.log 2>&1
```

### 14. Continuous Security Monitoring
```bash
#!/bin/bash
# monitoring_scan.sh - Daily vulnerability scan

DATE=$(date +%Y%m%d)
LOG_FILE="/var/log/security-scan-$DATE.log"

# Run scan and log results
./advanced_lowhanging_scanner.sh \
  --config production_config.conf \
  >> "$LOG_FILE" 2>&1

# Alert if critical vulnerabilities found
if grep -q "CRITICAL VULNERABILITIES FOUND" "$LOG_FILE"; then
    echo "🚨 CRITICAL vulnerabilities detected!" | \
    mail -s "Security Alert - $DATE" security-team@company.com
fi
```

## Troubleshooting Common Issues

### Issue: No hosts found
```bash
# Test network connectivity
nmap -sn 192.168.1.0/24

# Check if target subnet is correct
./demo_scanner.sh  # Use demo for quick verification
```

### Issue: Permission denied
```bash
# Run with sudo for SYN scanning (faster)
sudo ./advanced_lowhanging_scanner.sh

# Or use without sudo (TCP connect - slower but works)
./advanced_lowhanging_scanner.sh  # Will auto-detect and use -sT
```

### Issue: NetExec module errors
```bash
# Test NetExec installation
nxc smb 127.0.0.1

# Update NetExec
pip install --upgrade netexec
```

## Performance Tuning

### For Small Networks (< 100 hosts)
```bash
MAX_PARALLEL=10
TIMEOUT_PER_HOST=300
```

### For Medium Networks (100-1000 hosts)
```bash
MAX_PARALLEL=25  
TIMEOUT_PER_HOST=180
```

### For Large Networks (> 1000 hosts)
```bash
MAX_PARALLEL=50
TIMEOUT_PER_HOST=120
NMAP_THREADS=500
```

---

**Remember**: Always ensure you have proper authorization before scanning any networks!

*Happy Hunting! 🔥*
