{
  lib,
  stdenv,
  mkShell,
  toolchain,
  rust-analyzer,
  tombi,
  clang,
  wild,
  pkg-config,
  libghostty-vt,
  pam,
  extraPackages ? [ ],
}:
mkShell {
  name = "quicsh";

  strictDeps = true;

  nativeBuildInputs = [
    toolchain
    rust-analyzer
    tombi
    pkg-config
  ]
  ++ lib.optionals stdenv.hostPlatform.isLinux [
    clang
    wild
  ]
  ++ extraPackages;

  buildInputs = [
    libghostty-vt
  ]
  ++ lib.optional stdenv.hostPlatform.isLinux pam;

  env = {
    RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
  }
  // lib.optionalAttrs stdenv.hostPlatform.isLinux {
    RUSTFLAGS = "-Clinker=${clang}/bin/clang -Clink-arg=--ld-path=wild";
  };
}
