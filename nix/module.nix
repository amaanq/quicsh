# NixOS module for qshd.
#
# ```nix
# services.qshd.enable = true;
# ```
#
# This listens on UDP port 22, opens it in the firewall and reuses the
# OpenSSH host key, which it generates when sshd never did.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.qshd;
in
{
  options.services.qshd = {
    enable = lib.mkEnableOption "the quicsh server";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The quicsh package to run. The flake's `nixosModules.qshd` defaults
        this to `packages.<system>.quicsh`. Set it yourself when importing
        `nix/module.nix` directly.
      '';
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "[::]";
      example = "192.0.2.1";
      description = "Address to listen on. An IPv6 address also serves IPv4.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 22;
      description = "UDP port to listen on.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Open the UDP port in the firewall.";
    };

    hostKey = lib.mkOption {
      type = lib.types.path;
      default = "/etc/ssh/ssh_host_ed25519_key";
      description = ''
        The host key in OpenSSH format, an ed25519, P-256 or P-384 key. An ed25519
        key is generated when missing.
      '';
    };

    authorizedKeysFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Check every login against this file. By default each account's own
        `~/.ssh/authorized_keys` decides.
      '';
    };

    sftpServer = lib.mkOption {
      type = lib.types.path;
      default = "${pkgs.openssh}/libexec/sftp-server";
      defaultText = lib.literalExpression ''"''${pkgs.openssh}/libexec/sftp-server"'';
      description = ''
        The program behind the `sftp` subsystem, which `scp` and `sftp` use.
      '';
    };

    acceptEnv = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "LANG"
        "LC_*"
        "COLORTERM"
      ];
      description = ''
        Patterns for the environment variables a client may set with
        `SendEnv` and `SetEnv`.
      '';
    };

    congestion = lib.mkOption {
      type = lib.types.enum [
        "bbr"
        "cubic"
      ];
      default = "bbr";
      description = "Congestion controller for what the server sends.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "qshd";
      description = ''
        Account for the unprivileged process that speaks to the network. The
        default account is created.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users = lib.mkIf (cfg.user == "qshd") {
      qshd = {
        isSystemUser = true;
        group = "qshd";
        description = "quicsh network process";
      };
    };

    users.groups = lib.mkIf (cfg.user == "qshd") { qshd = { }; };

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    environment.systemPackages = [ cfg.package ];

    systemd.services.qshd = {
      description = "quicsh server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      # Sessions inherit this and their shells add to it.
      environment.PATH = lib.mkForce "/run/wrappers/bin:/run/current-system/sw/bin";

      preStart = ''
        if ! [ -s ${lib.escapeShellArg cfg.hostKey} ]; then
          mkdir -p "$(dirname ${lib.escapeShellArg cfg.hostKey})"
          ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -f ${lib.escapeShellArg cfg.hostKey}
        fi
      '';

      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [
            (lib.getExe' cfg.package "qshd")
            "--listen"
            "${cfg.listenAddress}:${toString cfg.port}"
            "--host-key"
            cfg.hostKey
            "--user"
            cfg.user
            "--congestion"
            cfg.congestion
            "--sftp-server"
            cfg.sftpServer
          ]
          ++ lib.optionals (cfg.authorizedKeysFile != null) [
            "--authorized-keys"
            cfg.authorizedKeysFile
          ]
          ++ lib.concatMap (pattern: [
            "--accept-env"
            pattern
          ]) cfg.acceptEnv
        );
        Restart = "on-failure";
        # Sessions live in holder processes that a restarted server
        # picks up again, so only the server itself gets the signal.
        KillMode = "process";
      };
    };
  };
}
