{
  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.zst";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }@inputs:
    let
      inherit (inputs) nixpkgs fenix;
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          toolchain = fenix.packages.${system}.minimal.toolchain;

          quicsh = pkgs.callPackage ./nix/package.nix {
            rustPlatform = pkgs.makeRustPlatform {
              cargo = toolchain;
              rustc = toolchain;
            };
          };
        in
        {
          inherit quicsh;
          default = quicsh;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rust = fenix.packages.${system};
        in
        {
          default = pkgs.callPackage ./nix/shell.nix {
            inherit (rust) rust-analyzer;

            toolchain = rust.complete.withComponents [
              "cargo"
              "clippy"
              "rust-src"
              "rustc"
              "rustfmt"
            ];
          };
        }
      );

      nixosModules.qshd =
        { pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.qshd.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.quicsh;
        };
      nixosModules.default = self.nixosModules.qshd;

      checks = forAllSystems (system: {
        quicsh = self.packages.${system}.quicsh;
      });

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
