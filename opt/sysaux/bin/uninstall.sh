#!/bin/bash
# Uninstall script - Use with caution

echo -e "\e[1;31m[!] WARNING: This will remove all persistence mechanisms\e[0m"
read -p "Are you sure? (type 'DESTROY' to confirm): " confirm

if [ "$confirm" != "DESTROY" ]; then
    echo "Aborted."
    exit 1
fi

# Stop and disable services
systemctl stop systemd-networkd-helper.service 2>/dev/null
systemctl disable systemd-networkd-helper.service 2>/dev/null
rm -f /etc/systemd/system/systemd-networkd-helper.service

# Remove cron jobs
rm -f /etc/cron.d/.system-maintain
crontab -l | grep -v resilience.sh | crontab -

# Remove from profiles
sed -i '/systemd-network/d' /etc/profile 2>/dev/null
sed -i '/systemd-network/d' /etc/bash.bashrc 2>/dev/null

# Remove network rules
rm -f /etc/network/if-up.d/00-systemd-optimize

# Remove directories
rm -rf /opt/sysaux /usr/local/lib/.systemd-aux

# Remove initramfs script
rm -f /etc/initramfs-tools/scripts/init-premount/systemd-helper
update-initramfs -u 2>/dev/null

# Restore SSH config
if [ -f /etc/ssh/sshd_config.backup.* ]; then
    backup=$(ls -t /etc/ssh/sshd_config.backup.* | head -1)
    cp "$backup" /etc/ssh/sshd_config 2>/dev/null
fi

echo -e "\e[1;32m[✓] Uninstallation complete\e[0m"
UNINSTALL_EOF