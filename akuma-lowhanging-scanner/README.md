# 🔥 AKUMA's Advanced Low-Hanging Fruit Scanner 🔥

**"If your infrastructure isn't crying after this script - you're doing something wrong"**

Advanced penetration testing framework for discovering and exploiting low-hanging fruits in Windows/Linux infrastructures. Built with modular architecture, intelligent vulnerability detection, and comprehensive reporting.

## ⚡ Features

### 🎯 Comprehensive Service Discovery
- **Smart Port Scanning** - Optimized nmap parameters for speed and accuracy
- **Multi-Protocol Support** - SMB, LDAP, RDP, WinRM, HTTP, SSH, FTP, MSSQL
- **Adaptive Scanning** - Automatically switches between SYN/TCP Connect based on privileges

### 🔍 Advanced Vulnerability Detection
- **Critical Vulnerabilities**: Zerologon, MS17-010 (EternalBlue), SMBGhost, PrintNightmare
- **High Priority**: Authentication Coercion attacks, LSASSY, Nanodump
- **Medium Priority**: LDAP enumeration, LAPS, GPP passwords
- **Authenticated Attacks** - Full module suite when credentials provided

### 📊 Intelligent Reporting
- **Priority-based Classification** - Vulnerabilities sorted by criticality
- **Multiple Output Formats** - Text summaries and HTML reports
- **Evidence Collection** - Detailed logs and proof-of-concept data
- **Real-time Progress** - Color-coded status updates

## 🚀 Quick Start

### Prerequisites
```bash
# Install required tools
apt update && apt install nmap netcat-openbsd
pip install netexec
```

### Basic Usage
```bash
# Clone the repository
git clone <repository-url>
cd akuma-lowhanging-scanner

# Make scripts executable
chmod +x *.sh

# Quick demo scan
./demo_scanner.sh

# Full scan with default configuration
./advanced_lowhanging_scanner.sh

# Authenticated scan with credentials
./advanced_lowhanging_scanner.sh --auth --username admin --password password123
```

## 📁 Project Structure

```
akuma-lowhanging-scanner/
├── advanced_lowhanging_scanner.sh    # Main scanner (full functionality)
├── vuln_tester.sh                    # Quick vulnerability tester
├── demo_scanner.sh                   # Demo/testing version
├── scanner_config.conf               # Configuration file
├── README.md                         # This file
├── CHANGELOG.md                      # Version history
└── examples/                         # Usage examples
```

## ⚙️ Configuration

Edit `scanner_config.conf` to customize:

```bash
# Target subnets (space-separated)
SUBNETS=(
    "192.168.1.0/24"
    "10.0.0.0/24"
)

# Performance settings
MAX_PARALLEL=20
TIMEOUT_PER_HOST=300
NMAP_THREADS=100

# Authentication (for advanced modules)
AUTHENTICATED_SCAN=true
USERNAME="pentester"
PASSWORD="YourPasswordHere"
DOMAIN="CORP"

# Debug mode
DEBUG_MODE=false
```

## 🎯 Vulnerability Modules

### 🔴 Critical (Priority 1)
- **zerologon** - CVE-2020-1472 Domain Controller privilege escalation
- **ms17-010** - EternalBlue RCE (WannaCry/NotPetya fame)
- **smbghost** - CVE-2020-0796 Windows 10 RCE
- **printnightmare** - CVE-2021-34527 Print Spooler RCE
- **petitpotam** - NTLM Relay attack vector

### 🟠 High Priority (Priority 2)
- **spooler** - Print Spooler service enumeration
- **coerce_plus** - Authentication coercion attacks
- **lsassy** - LSASS memory dumping
- **nanodump** - Advanced LSASS dumping

### 🟡 Medium Priority (Priority 3)
- **enum_trusts** - Active Directory trust enumeration
- **ldap-checker** - LDAP configuration analysis
- **gpp_password** - Group Policy Preferences passwords
- **laps** - Local Administrator Password Solution

### 🔵 Authenticated Modules
- **bloodhound** - AD attack path analysis
- **dcsync** - DCSync attack simulation
- **kerberoasting** - Kerberos ticket extraction
- **secrets** - Credential extraction

## 📋 Usage Examples

### Basic Network Scan
```bash
./advanced_lowhanging_scanner.sh
```

### Targeted Subnet with Authentication
```bash
./advanced_lowhanging_scanner.sh \
  --auth \
  --username "admin" \
  --password "P@ssw0rd123" \
  --domain "CORP" \
  --debug
```

### Quick Vulnerability Test
```bash
# Test specific vulnerabilities on discovered hosts
./vuln_tester.sh
```

### Custom Configuration
```bash
./advanced_lowhanging_scanner.sh --config /path/to/custom.conf
```

## 📊 Output Structure

```
~/lowhanging_results/scan_YYYYMMDD_HHMMSS/
├── scanner.log                    # Main execution log
├── *_hosts.txt                   # Discovered hosts by service
├── logs/                          # Individual module logs
├── results/                       # Vulnerability findings
├── raw_results/                   # Raw discovery data
├── reports/
│   ├── vulnerability_summary.txt  # Executive summary
│   └── detailed_report.html      # Comprehensive HTML report
└── evidence/                      # Proof-of-concept data
```

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED PENETRATION TESTING ONLY**

This tool is designed for legitimate security testing and research purposes. Users are responsible for:
- Obtaining proper authorization before scanning any networks
- Complying with local laws and regulations
- Using the tool ethically and responsibly

The developers are not responsible for any misuse of this software.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-module`)
3. Commit your changes (`git commit -m 'Add amazing vulnerability module'`)
4. Push to the branch (`git push origin feature/amazing-module`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Credits

Developed by **AKUMA** - Penetration Testing Specialist

Built with:
- [NetExec](https://github.com/Pennyw0rth/NetExec) - Network execution toolkit
- [nmap](https://nmap.org/) - Network discovery and security auditing
- Bash scripting mastery and too much caffeine ☕

---

**Remember: With great power comes great responsibility... and potentially jail time if you're stupid about it.**

*Happy Hacking! 🔥*
