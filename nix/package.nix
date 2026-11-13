{
  lib,
  rustPlatform,
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
        (s + /src)
        (s + /vendor)
        (s + /Cargo.lock)
        (s + /Cargo.toml)
      ];
    };

  cargoLock.lockFile = ../Cargo.lock;

  strictDeps = true;
  enableParallelBuilding = true;

  meta = {
    inherit (cargoTOML) description;
    homepage = cargoTOML.repository;
    license = lib.licenses.eupl12;
    maintainers = with lib.maintainers; [ amaanq ];
    mainProgram = "qsh";
    platforms = lib.platforms.linux;
  };
}
