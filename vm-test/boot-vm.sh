#!/usr/bin/env bash
# Boot the test VM in the FOREGROUND with the serial console on this
# terminal — run it in its own window.  run-vm-test.sh will then use this
# VM instead of booting its own daemonized one.
#
# Requires vm-test/state/ to exist already (run run-vm-test.sh once, or at
# least let it get through image download and seed generation).
#
# Console notes:
#   - Ctrl-A x exits qemu, Ctrl-A c toggles the qemu monitor.
#   - Console login needs a root password; the image ships with it locked.
#     Set one first over ssh:
#       ssh -i state/id_ed25519 -p 10022 root@localhost passwd

set -euo pipefail

cd "$(dirname "$0")"
# Absolute so the qemu command line identifies *this* worktree's image:
# the pgrep guard below must not match a VM booted from another worktree.
STATE=$PWD/state
SSH_PORT=${SSH_PORT:-10022}
MEM=${MEM:-4G}
CPUS=${CPUS:-4}

for f in base.qcow2 seed.iso; do
    if [ ! -f "$STATE/$f" ]; then
        echo "$STATE/$f missing — run ./run-vm-test.sh first" >&2
        exit 1
    fi
done

if [ ! -f "$STATE/overlay.qcow2" ]; then
    echo "creating fresh overlay (previous VM state discarded)"
    qemu-img create -f qcow2 -b base.qcow2 -F qcow2 \
        "$STATE/overlay.qcow2.tmp" 20G
    mv "$STATE/overlay.qcow2.tmp" "$STATE/overlay.qcow2"
fi

if pgrep -af "$STATE/overlay.qcow2" >/dev/null; then
    echo "a VM is already using the image:" >&2
    pgrep -af "$STATE/overlay.qcow2" >&2
    echo "use it, or stop it first (foreground: Ctrl-A x; daemonized:" \
        "kill \$(cat $STATE/qemu.pid))" >&2
    exit 1
fi

exec qemu-system-x86_64 \
    -machine q35 -accel kvm -m "$MEM" -smp "$CPUS" \
    -drive file="$STATE/overlay.qcow2",if=virtio \
    -cdrom "$STATE/seed.iso" \
    -nic user,model=virtio,hostfwd=tcp::"$SSH_PORT"-:22 \
    -display none -serial mon:stdio
