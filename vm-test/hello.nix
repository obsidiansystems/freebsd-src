# Cross-build GNU hello against FreeBSD *main* userland — smoke test
# for the full main-branch toolchain (libc, csu, rtld, clang wrapper).
#   nix-build vm-test/hello.nix
{
  nixpkgs ? /home/jcericson/src/nixpkgs-master,
}:
let
  pkgs = import nixpkgs {
    crossSystem = {
      config = "x86_64-unknown-freebsd";
    };
    overlays = [
      (final: prev: {
        freebsd = prev.freebsd.override { branch = "main"; };
      })
    ];
  };
in
pkgs.hello
