#!/usr/bin/env bash
# Boot a FreeBSD CURRENT cloud image under qemu, optionally install a
# cross-built kernel, and run the unix_connectat tests in it.
#
# Usage:
#   run-vm-test.sh                # stock snapshot kernel (expect new tests to fail)
#   run-vm-test.sh <kernel-dir>   # e.g. $MAKEOBJDIRPREFIX/.../amd64.amd64/sys/GENERIC
#
# State (image, overlay, ssh key) lives in vm-test/state/ and is reused
# across runs.  Delete state/overlay.qcow2 to reset the VM, or all of
# state/ to re-download.

set -euo pipefail

# Resolve the kernel dir argument before changing directory.
if [ -n "${1:-}" ]; then
    set -- "$(realpath "$1")"
fi
cd "$(dirname "$0")"
SRCDIR=$(cd .. && pwd)
# Absolute so the qemu command line identifies *this* worktree's image:
# the pgrep guard below must not match a VM booted from another worktree.
STATE=$PWD/state
SSH_PORT=${SSH_PORT:-10022}
MEM=${MEM:-4G}
CPUS=${CPUS:-4}
IMG_URL=${IMG_URL:-https://download.freebsd.org/snapshots/VM-IMAGES/16.0-CURRENT/amd64/Latest/FreeBSD-16.0-CURRENT-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz}
KERNEL_DIR=${1:-}

mkdir -p "$STATE"

# On ^C: remove partial artifacts, and kill qemu only if *we* were still
# booting it — a VM that reached ssh (or predates this run) is left running.
STARTED_QEMU=
cleanup() {
    rm -f "$STATE"/*.tmp
    if [ -n "$STARTED_QEMU" ] && [ -f "$STATE/qemu.pid" ]; then
        echo "interrupted during boot; stopping qemu" >&2
        kill "$(cat "$STATE/qemu.pid")" 2>/dev/null || true
        rm -f "$STATE/qemu.pid"
    fi
    trap - INT TERM
    exit 130
}
trap cleanup INT TERM

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=5 -o LogLevel=ERROR -i "$STATE/id_ed25519" -p "$SSH_PORT")
vm() { ssh "${SSH_OPTS[@]}" "root@localhost" "$@"; }
vmcp() { scp "${SSH_OPTS[@]/-p/-P}" "$@"; }

wait_ssh() {
    echo "waiting for ssh..."
    for _ in $(seq 120); do
        if vm true 2>/dev/null; then return 0; fi
        sleep 5
    done
    echo "VM never became reachable" >&2
    exit 1
}

# --- one-time setup -------------------------------------------------------

[ -f "$STATE/id_ed25519" ] ||
    ssh-keygen -t ed25519 -N "" -f "$STATE/id_ed25519" -C freebsd-vm-test

if [ ! -f "$STATE/base.qcow2" ]; then
    echo "fetching $IMG_URL"
    curl -L --fail -o "$STATE/base.qcow2.xz.tmp" "$IMG_URL"
    xz -dc "$STATE/base.qcow2.xz.tmp" > "$STATE/base.qcow2.tmp"
    mv "$STATE/base.qcow2.tmp" "$STATE/base.qcow2"
    rm -f "$STATE/base.qcow2.xz.tmp"
fi

if [ ! -f "$STATE/overlay.qcow2" ]; then
    qemu-img create -f qcow2 -b base.qcow2 -F qcow2 "$STATE/overlay.qcow2.tmp" 20G
    mv "$STATE/overlay.qcow2.tmp" "$STATE/overlay.qcow2"
fi

# Regenerated every run (cheap); a fresh overlay picks up changes.
# Skipped when genisoimage is unavailable (e.g. outside the nix shell)
# and a seed already exists — the content rarely changes.
# The key must land on root explicitly: FreeBSD cloud-init gives
# top-level ssh_authorized_keys to the default user only, and base
# sshd has PermitRootLogin off.
KEY=$(cat "$STATE/id_ed25519.pub")
printf 'instance-id: freebsd-vm-test-2\nlocal-hostname: fbsd-test\n' \
    > "$STATE/meta-data"
cat > "$STATE/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - $KEY
runcmd:
  - mkdir -p /root/.ssh
  - chmod 700 /root/.ssh
  - printf '%s\n' '$KEY' > /root/.ssh/authorized_keys
  - chmod 600 /root/.ssh/authorized_keys
  - printf 'PermitRootLogin prohibit-password\n' >> /etc/ssh/sshd_config
  - service sshd restart
EOF
if command -v genisoimage >/dev/null; then
    genisoimage -quiet -output "$STATE/seed.iso.tmp" -volid cidata \
        -joliet -rock "$STATE/user-data" "$STATE/meta-data"
    mv "$STATE/seed.iso.tmp" "$STATE/seed.iso"
elif [ ! -f "$STATE/seed.iso" ]; then
    echo "genisoimage not found and no existing seed.iso" >&2
    exit 1
else
    echo "note: genisoimage unavailable, reusing existing seed.iso"
fi

# --- boot -----------------------------------------------------------------

if ! vm true 2>/dev/null; then
    if pgrep -f "$STATE/overlay.qcow2" >/dev/null; then
        # A VM (e.g. boot-vm.sh in another terminal) is already using the
        # image but hasn't finished booting — wait for it, don't race it.
        echo "existing qemu holds the image; waiting for it to come up"
        wait_ssh
    else
        echo "booting VM (console: $STATE/console.log)"
        STARTED_QEMU=1
        qemu-system-x86_64 \
            -machine q35 -accel kvm -m "$MEM" -smp "$CPUS" \
            -drive file="$STATE/overlay.qcow2",if=virtio \
            -cdrom "$STATE/seed.iso" \
            -nic user,model=virtio,hostfwd=tcp::"$SSH_PORT"-:22 \
            -display none -daemonize \
            -serial file:"$STATE/console.log" \
            -pidfile "$STATE/qemu.pid"
        wait_ssh
        STARTED_QEMU=
    fi
fi

# --- install kernel -------------------------------------------------------

if [ -n "$KERNEL_DIR" ]; then
    want=$(sha256sum "$KERNEL_DIR/kernel" | cut -d' ' -f1)
    # Only install when the VM is not already running this kernel: the reboot
    # costs ~30s, and a tests-only change does not need it.  Note a rebuild
    # embeds a fresh version string, so an unchanged tree that was rebuilt
    # anyway still counts as a different kernel.
    if [ "$(vm "sha256 -q \$(sysctl -n kern.bootfile)" 2>/dev/null)" = "$want" ]
    then
        echo "kernel from $KERNEL_DIR already booted; skipping install"
    else
        echo "installing kernel from $KERNEL_DIR"
        vm "rm -rf /boot/kernel.test && mkdir -p /boot/kernel.test"
        # Just the kernel: GENERIC has everything the VM and these tests
        # need built in, so no modules are shipped.
        vmcp "$KERNEL_DIR/kernel" root@localhost:/boot/kernel.test/kernel
        vm "nextboot -k kernel.test && shutdown -r now" || true
        sleep 10
        wait_ssh
    fi
fi

echo "kernel under test:"
vm "uname -a; sysctl -n kern.bootfile"
if [ -n "$KERNEL_DIR" ]; then
    got=$(vm "sha256 -q \$(sysctl -n kern.bootfile)")
    if [ "$want" = "$got" ]; then
        echo "kernel identity verified: sha256 $got"
    else
        echo "kernel MISMATCH: built $want, running $got" >&2
        exit 1
    fi
fi

# --- run tests ------------------------------------------------------------

# unix_seqpacket_test is rebuilt too, not just unix_connectat: the image's
# installed copy predates this branch and still expects listen(2) on an
# unbound socket to fail, so it reports the new behaviour as a failure.
vmcp "$SRCDIR/tests/sys/kern/unix_connectat.c" \
     "$SRCDIR/tests/sys/kern/unix_seqpacket_test.c" root@localhost:
vm "cc -o unix_connectat unix_connectat.c -lprivateatf-c -lutil"
vm "cc -o unix_seqpacket_test unix_seqpacket_test.c -lprivateatf-c -lpthread"

# Smoke-run the cases that need no fdescfs mount.  The fdescfs ones are left
# to kyua below: run directly the cleanup routine that unmounts does not fire,
# and the mount would then defeat the rm -rf here.
rc=0
for t in stream stream_bound dgram empty_path_vnode path bind_after_listen \
         listen_after_disconnect empty_path_at_fdcwd \
         bad_peers cap_connectat cap_connectat_denied; do
    if out=$(vm "d=\$(mktemp -d) && cd \$d && \$HOME/unix_connectat $t; r=\$?; rm -rf \$d; exit \$r" 2>&1); then
        echo "PASS $t"
    else
        echo "FAIL $t"
        echo "$out" | sed 's/^/     /'
        rc=1
    fi
done

# Install both over the image's copies, and register the new one with the
# suite so kyua runs it too (unix_seqpacket_test is already listed).
vm "cp unix_connectat /usr/tests/sys/kern/unix_connectat
    cp unix_seqpacket_test /usr/tests/sys/kern/unix_seqpacket_test
    if ! grep -q unix_connectat /usr/tests/sys/kern/Kyuafile; then
        echo 'atf_test_program{name=\"unix_connectat\"}' >> /usr/tests/sys/kern/Kyuafile
    fi"

echo "kyua: unix_connectat + existing unix socket tests"
vm "kyua test -k /usr/tests/sys/kern/Kyuafile unix_connectat unix_stream \
    unix_dgram unix_seqpacket_test; kyua report --verbose | tail -20" || rc=1

exit $rc
