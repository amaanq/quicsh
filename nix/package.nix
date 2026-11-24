{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  libghostty-vt,
  pam,
}:
let
  cargoTOML = (lib.importTOML ../Cargo.toml).package;
in
rustPlatform.buildRustPackage {
  pname = cargoTOML.name;
  inherit (cargoTOML) version;

  src =
    let
      fs = lib.fileset;
      s = ../.;
    in
    fs.toSource {
      root = s;
      fileset = fs.unions [
        (s + /pam)
        (s + /src)
        (s + /vendor)
        (s + /vt)
        (s + /Cargo.lock)
        (s + /Cargo.toml)
      ];
    };

  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    libghostty-vt
  ]
  ++ lib.optional stdenv.hostPlatform.isLinux pam;

  strictDeps = true;
  enableParallelBuilding = true;

  meta = {
    inherit (cargoTOML) description;
    homepage = cargoTOML.repository;
    license = lib.licenses.eupl12;
    maintainers = with lib.maintainers; [ amaanq ];
    mainProgram = "qsh";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
