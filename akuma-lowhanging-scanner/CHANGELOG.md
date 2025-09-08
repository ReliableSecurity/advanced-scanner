# Changelog

All notable changes to AKUMA's Advanced Low-Hanging Fruit Scanner will be documented in this file.

## [2.0.0] - 2025-09-08

### 🔥 Major Release - Complete Rewrite

#### Added
- **Modular Architecture** - Complete redesign with priority-based vulnerability classification
- **Advanced Service Discovery** - Multi-protocol scanning (SMB, LDAP, RDP, WinRM, HTTP, SSH, FTP, MSSQL)  
- **Intelligent Vulnerability Detection** - Improved pattern matching for "Potentially vulnerable" results
- **Authenticated Scanning** - Full NetExec module suite with credential support
- **Comprehensive Reporting** - HTML and text reports with vulnerability prioritization
- **Adaptive Scanning** - Automatically switches between SYN/TCP Connect based on privileges
- **Real-time Progress** - Color-coded status updates and debug logging

#### Critical Vulnerability Modules
- **zerologon** - CVE-2020-1472 Domain Controller attacks
- **ms17-010** - EternalBlue RCE (WannaCry/NotPetya)
- **smbghost** - CVE-2020-0796 Windows 10/Server 2019 RCE
- **printnightmare** - CVE-2021-34527 Print Spooler RCE
- **petitpotam** - NTLM Relay attack vectors

#### High Priority Modules
- **spooler** - Print Spooler service enumeration
- **coerce_plus** - Authentication coercion attacks
- **lsassy** - LSASS memory dumping
- **nanodump** - Advanced LSASS extraction

#### Medium Priority Modules  
- **enum_trusts** - Active Directory trust enumeration
- **ldap-checker** - LDAP configuration analysis
- **gpp_password** - Group Policy Preferences passwords
- **laps** - Local Administrator Password Solution
- **adcs** - Active Directory Certificate Services

#### Authenticated Modules
- **bloodhound** - AD attack path analysis
- **dcsync** - DCSync attack simulation  
- **kerberoasting** - Kerberos ticket extraction
- **asreproast** - AS-REP Roasting attacks
- **secrets** - Advanced credential extraction

#### Performance Improvements
- **Parallel Processing** - Configurable concurrent host scanning (default: 20)
- **Optimized nmap Parameters** - Fast discovery with accuracy
- **Intelligent Timeouts** - Per-host timeout configuration
- **Memory Management** - Automatic log archiving and cleanup

#### Enhanced Reporting
- **Executive Summary** - High-level vulnerability overview
- **Detailed HTML Reports** - Color-coded findings with timestamps
- **Evidence Collection** - Detailed logs and proof-of-concept data
- **Statistics Tracking** - Host count and service enumeration

### Fixed
- **Root Privilege Detection** - Properly handles SYN vs TCP Connect scanning
- **Vulnerability Pattern Matching** - Improved detection of "Potentially vulnerable" results
- **Directory Creation** - Fixed race condition in output directory creation
- **NetExec Integration** - Better error handling and result parsing
- **Configuration Loading** - Proper config file validation and defaults

### Testing Results
Tested on subnet 192.168.112.0/22:
- **79 Live Hosts** discovered
- **21 SMB Hosts** found and tested
- **Multiple Critical Vulnerabilities** detected:
  - SMBGhost vulnerabilities on 3 hosts
  - MS17-010 potential targets identified
  - Authentication coercion vectors found

## [1.0.0] - 2025-09-07

### Initial Release
- Basic SMB vulnerability scanning
- Simple nmap host discovery  
- Limited NetExec module integration
- Basic reporting functionality

---

## Planned Features

### [2.1.0] - Future Release
- **Web Interface** - Django/Flask web dashboard
- **Database Storage** - PostgreSQL/SQLite result storage
- **API Integration** - RESTful API for programmatic access
- **Custom Modules** - Plugin architecture for custom vulnerability checks
- **Scheduled Scanning** - Cron-based automated scans
- **Notification System** - Slack/Email alerts for critical findings

### [3.0.0] - Future Major Release
- **Machine Learning** - AI-powered vulnerability prioritization
- **Exploitation Framework** - Automated exploit deployment
- **Reporting Templates** - Customizable report formats
- **Multi-Threading** - Advanced concurrent processing
- **Cloud Integration** - AWS/Azure/GCP scanning capabilities
