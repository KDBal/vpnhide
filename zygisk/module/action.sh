#!/system/bin/sh
# Magisk action button — show current vpnhide status and targets.

PERSIST_DIR="/data/adb/vpnhide_zygisk"
TARGETS_FILE="$PERSIST_DIR/targets.txt"
MODULE_DIR="${0%/*}"

echo "=== VPN Hide (Zygisk) ==="
echo ""

# Show targets
if [ -f "$TARGETS_FILE" ]; then
    count=$(grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | wc -l)
    echo "Targets ($count):"
    grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | while read -r pkg; do
        echo "  - $pkg"
    done
else
    echo "No targets configured."
fi

echo ""

# Show module dir copy status
if [ -f "$MODULE_DIR/targets.txt" ]; then
    echo "Module dir copy: OK"
else
    echo "Module dir copy: MISSING (will be created on next reboot)"
fi

# Show lsposed UIDs file
SS_UIDS="/data/system/vpnhide_uids.txt"
if [ -f "$SS_UIDS" ]; then
    uid_count=$(wc -l < "$SS_UIDS")
    echo "LSPosed UIDs file: $uid_count UIDs"
else
    echo "LSPosed UIDs file: not found"
fi

echo ""
echo "=== Manage targets ==="
echo ""
echo "Edit targets via adb shell:"
echo "  su -c 'echo com.example.app >> $TARGETS_FILE'"
echo "  su -c 'vi $TARGETS_FILE'"
echo ""
echo "After editing, reboot for changes to take effect."
echo "On KernelSU, use the WebUI instead."
