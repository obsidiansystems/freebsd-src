# Build a FreeBSD-main kernel (GENERIC) with the nixpkgs FreeBSD
# infrastructure.  Requires a nixpkgs with the freebsd branch-main
# support (versions.json main + patches/16.0).
#   nix-build vm-test/kernel.nix                  # this tree's kernel
#   nix-build vm-test/kernel.nix --arg src null   # pure upstream main
# Result: ./result/kernel/kernel  ->  ./vm-test/run-vm-test.sh result/kernel
{
  nixpkgs ? /home/jcericson/src/nixpkgs-master,
  src ? ../.,
}:
let
  pkgs = import nixpkgs {
    crossSystem = {
      config = "x86_64-unknown-freebsd";
    };
    # Overlay so every stage (build tools, target) is uniformly main —
    # mk files must match the source generation per package.
    overlays = [
      (final: prev: {
        freebsd = prev.freebsd.override { branch = "main"; };
      })
    ];
  };

  freebsd =
    if src == null then
      pkgs.freebsd
    else
      pkgs.freebsd.overrideScope (
        self: super: {
          # Impure local fetch: tracked files only (excludes stale build
          # junk), includes uncommitted changes to tracked files.
          source = builtins.fetchGit { url = src; };
        }
      );
in
freebsd.sys
