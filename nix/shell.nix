{
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
    clang
    wild
    pkg-config
  ]
  ++ extraPackages;

  buildInputs = [
    libghostty-vt
    pam
  ];

  env = {
    RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
    RUSTFLAGS = "-Clinker=${clang}/bin/clang -Clink-arg=--ld-path=wild";
  };
}
