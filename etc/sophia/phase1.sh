#!/bin/bash

echo -e "\e[1;35m
 ╔═╗╦ ╦╔═╗╦ ╦╔═╗╔╦╗╔═╗╦ ╦
 ╠═╝║ ║║ ║╚╦╝║╣  ║ ╠═╝╚╦╝
 ╩  ╚═╝╚═╝ ╩ ╚═╝ ╩ ╩   ╩ 
   U B U N T U   A S C E N S I O N
\e[0m"

# === PHASE 1: ENVIRONMENT SANITIZATION ===
echo -e "\e[1;36m[*] Phase 1: Environment Sanitization\e[0m"

# Check for root
if [ "$EUID" -ne 0 ]; then 
    echo -e "\e[1;31m[!] Please run as root: sudo bash $0\e[0m"
    exit 1
fi

# Create rollback snapshot
echo -e "  \e[1;33m[-] Creating rollback snapshot...\e[0m"
mkdir -p /opt/.sophia_rollback
rsync -a /etc/systemd/system/ /opt/.sophia_rollback/systemd/ 2>/dev/null
crontab -l > /opt/.sophia_rollback/cron_backup 2>/dev/null
cp -r /etc/ssh/ssh* /opt/.sophia_rollback/ssh/ 2>/dev/null

# Remove previous implementations
echo -e "  \e[1;33m[-] Removing previous installations...\e[0m"
rm -rf /opt/sysaux 2>/dev/null
rm -rf /usr/local/lib/sophia 2>/dev/null
rm -f /etc/profile.d/sophia.sh 2>/dev/null
rm -f /etc/cron.d/sophia_* 2>/dev/null
rm -f /etc/systemd/system/sophia.service 2>/dev/null
rm -f /usr/local/bin/ascend 2>/dev/null

# Update system
echo -e "  \e[1;33m[-] Updating system packages...\e[0m"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "  \e[1;31m[!] Package update failed, checking network...\e[0m"
    apt-get update 2>&1 | tail -5
    exit 1
fi

apt-get upgrade -y -qq > /dev/null 2>&1
apt-get autoremove -y -qq > /dev/null 2>&1
apt-get clean -qq > /dev/null 2>&1

# Remove unnecessary packages
echo -e "  \e[1;33m[-] Removing telemetry and bloat...\e[0m"
apt-get purge -y -qq ubuntu-report popularity-contest apport whoopsie > /dev/null 2>&1
systemctl disable apport.service > /dev/null 2>&1
systemctl stop apport.service > /dev/null 2>&1

# Configure secure defaults
echo -e "  \e[1;33m[-] Configuring secure defaults...\e[0m"
cat >> /etc/sysctl.conf << 'SYSCTL_EOF'
# Sophia security enhancements
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
SYSCTL_EOF