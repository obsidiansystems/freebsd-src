# Kernel dev shell: the build environment of the nixpkgs `freebsd.sys`
# derivation (cross clang, bmake + matching share/mk, config(8), setup
# hooks), plus the qemu VM harness tools.
#
#   nix-shell vm-test/shell.nix
#
# Impure incremental kernel builds against this working tree:
#
#   cd sys/amd64/conf
#   config -d $PWD/../compile/DEV GENERIC
#   cd ../compile/DEV
#   bmake -j$(nproc) $makeFlags
#   bmake $makeFlags install KODIR=/tmp/kernel-dev   # then run-vm-test.sh /tmp/kernel-dev
#
# The objdir persists across shells, so rebuilds after editing are
# incremental — no nix rebuild of the whole kernel needed.
{
  nixpkgs ? /home/jcericson/src/nixpkgs-master,
}:
let
  kernel = import ./kernel.nix { inherit nixpkgs; };
  nativePkgs = import nixpkgs { };
in
kernel.overrideAttrs (old: {
  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ (
    with nativePkgs;
    [
      # VM harness (run-vm-test.sh / boot-vm.sh)
      qemu_kvm
      cdrkit # genisoimage, for the cloud-init seed ISO
      curl
      xz
      openssh
    ]
  );

  shellHook = (old.shellHook or "") + ''
    # Normally set by the post-unpack hook from $BSDSRCDIR; without it
    # share/mk derives SRCTOP from MAKESYSPATH, i.e. the bmake store
    # path.  Put it in makeFlags (command-line vars beat everything, and
    # env alone does not reliably reach module sub-makes).
    export SRCTOP=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
    export makeFlags="$makeFlags SRCTOP=$SRCTOP"
    echo "SRCTOP=$SRCTOP (also appended to \$makeFlags)"

    # The in-tree newvers.sh uses BSD date flags with SOURCE_DATE_EPOCH
    # (nixpkgs patches this only inside the sandboxed build); GNU date
    # chokes.  Dev builds don't need the pin — and real timestamps make
    # dev kernels distinguishable in uname(1).
    unset SOURCE_DATE_EPOCH
    echo "freebsd.sys dev shell — see vm-test/shell.nix header for the"
    echo "incremental build recipe; VM: vm-test/run-vm-test.sh <kernel-dir>"
  '';
})
