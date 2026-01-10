#!/bin/bash
# entrypoint.sh - Deus Ex Sophia Container Entrypoint
# This script executes the phase scripts to build the structure from README-1.md

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        Deus Ex Sophia - Ascension v5.0                    ║"
echo "║        Container Entrypoint                                ║"
echo "╚════════════════════════════════════════════════════════════╝"

# Run initialization first
if [ -f /init.sh ]; then
    echo "[*] Running initialization..."
    bash /init.sh
fi

# Execute phase scripts if they exist and SOPHIA_AUTO_START is enabled
if [ "${SOPHIA_AUTO_START:-true}" = "true" ]; then
    echo "[*] Auto-start enabled. Executing phase scripts..."
    
    # Phase 1-3: Foundation, Truth, and Persistence
    if [ -f /opt/sysaux/phases-1-3.sh ]; then
        echo "[*] Executing phases-1-3.sh..."
        bash /opt/sysaux/phases-1-3.sh || echo "[!] Warning: phases-1-3.sh failed"
    fi
    
    # Phase 4: Network Intelligence Expansion
    if [ -f /opt/sysaux/phases-4.sh ]; then
        echo "[*] Executing phases-4.sh..."
        bash /opt/sysaux/phases-4.sh || echo "[!] Warning: phases-4.sh failed"
    fi
    
    # Phase 5: Advanced Exfiltration Matrix
    if [ -f /opt/sysaux/phases-5.sh ]; then
        echo "[*] Executing phases-5.sh..."
        bash /opt/sysaux/phases-5.sh || echo "[!] Warning: phases-5.sh failed"
    fi
else
    echo "[*] Auto-start disabled. Phase scripts will not execute automatically."
    echo "[*] Execute manually: bash /opt/sysaux/phases-1-3.sh"
fi

# Check if a command was provided
if [ $# -eq 0 ]; then
    # Default: start dashboard if available, otherwise sleep
    if command -v ascend >/dev/null 2>&1; then
        echo "[*] Starting ascend dashboard..."
        exec ascend dashboard
    else
        echo "[*] No command specified. Keeping container alive..."
        exec tail -f /dev/null
    fi
else
    # Execute provided command
    echo "[*] Executing: $@"
    exec "$@"
fi
