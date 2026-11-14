{
  mkShell,
  toolchain,
  rust-analyzer,
  tombi,
  clang,
  wild,
  pkg-config,
  libghostty-vt,
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

  buildInputs = [ libghostty-vt ];

  env = {
    RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
    RUSTFLAGS = "-Clinker=${clang}/bin/clang -Clink-arg=--ld-path=wild";
  };
}
