{
  testers,
  openssh,
  rsync,
  runCommand,
  self,
  socat,
}:
let
  keys = runCommand "qshd-test-keys" { nativeBuildInputs = [ openssh ]; } ''
    mkdir $out
    ssh-keygen -q -t ed25519 -N "" -f $out/authority
    ssh-keygen -q -t ed25519 -N "" -f $out/host
    ssh-keygen -q -s $out/authority -h -I certified -n certified $out/host.pub
    ssh-keygen -q -t ed25519 -N "" -f $out/user
    cp $out/user $out/other
    cp $out/user.pub $out/other.pub
    ssh-keygen -q -s $out/authority -I alice -n alice $out/user.pub
    ssh-keygen -q -s $out/authority -I bob -n bob $out/other.pub
  '';
in
testers.runNixOSTest {
  name = "qshd";

  containers.certified = {
    imports = [ self.nixosModules.default ];

    services.qshd = {
      enable = true;
      openFirewall = true;
      hostKey = "${keys}/host";
      hostCertificate = "${keys}/host-cert.pub";
      acceptEnv = [ "PROBE_*" ];
      authorities = "${keys}/authority.pub";
    };

    users.users.alice.isNormalUser = true;
  };

  containers.server = {
    imports = [ self.nixosModules.default ];

    services.qshd = {
      enable = true;
      openFirewall = true;
    };

    users.users.alice.isNormalUser = true;

    environment.systemPackages = [ socat ];
  };

  containers.client =
    { pkgs, ... }:
    {
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.quicsh
        openssh
        rsync
        socat
      ];
    };

  testScript = /* py */ ''
    start_all()
    server.wait_for_unit("qshd.service")
    certified.wait_for_unit("qshd.service")
    client.wait_for_unit("multi-user.target")

    client.succeed("mkdir -p /root/.ssh && ssh-keygen -q -t ed25519 -N ''' -f /root/.ssh/id_ed25519")
    key = client.succeed("cat /root/.ssh/id_ed25519.pub").strip()

    server.succeed("install -d -m 700 -o alice /home/alice/.ssh")
    server.succeed(f"echo '{key}' > /home/alice/.ssh/authorized_keys")
    server.succeed("chown alice /home/alice/.ssh/authorized_keys")

    host = server.succeed("cat /etc/ssh/ssh_host_ed25519_key.pub").split()
    client.succeed(f"echo 'server {host[0]} {host[1]}' > /root/.ssh/known_hosts")

    with subtest("a remote command runs as the account"):
        assert "uid=1000(alice)" in client.succeed("qsh alice@server id")

    with subtest("scp and rsync copy files"):
        client.succeed("echo data > /tmp/file")
        client.succeed("scp -S qsh /tmp/file alice@server:copied")
        client.succeed("rsync -e qsh /tmp/file alice@server:synced")
        server.succeed("grep data /home/alice/copied /home/alice/synced")

    with subtest("an accepted environment variable reaches the session"):
        assert "LC_PROBE=sent" in client.succeed("qsh -o 'SetEnv LC_PROBE=sent' alice@server env")

    with subtest("certificates stand in for a known host key and a listed login key"):
        client.succeed("echo '@cert-authority certified '$(cat ${keys}/authority.pub) >> /root/.ssh/known_hosts")
        client.succeed("install -m 600 ${keys}/user* ${keys}/other* /root/")
        assert "uid=1000(alice)" in client.succeed("qsh -o BatchMode=yes -i /root/user alice@certified id")
        client.fail("qsh -o BatchMode=yes -i /root/other alice@certified id")

    with subtest("only the listed environment patterns are accepted"):
        sent = client.succeed("qsh -i /root/user -o 'SetEnv PROBE_ONE=sent LC_PROBE=sent' alice@certified env")
        assert "PROBE_ONE=sent" in sent
        assert "LC_PROBE" not in sent

    with subtest("a forwarded Unix socket belongs to the account"):
        client.succeed("(qsh -N -R /home/alice/forward.sock:localhost:1 alice@server >/dev/null 2>&1 &)")
        server.wait_until_succeeds("test \"$(stat -c %U /home/alice/forward.sock)\" = alice", timeout=30)

    with subtest("a terminal session survives a restart of the service"):
        client.succeed(
            "(sleep 600 | script -qfc \"qsh -t alice@server 'sleep 20; echo survived > after'\""
            " /tmp/out >/dev/null 2>&1 &)"
        )
        server.wait_until_succeeds("pgrep -u alice sleep")
        server.succeed("systemctl restart qshd.service")
        server.wait_for_unit("qshd.service")
        server.succeed("pgrep -u alice sleep")
        server.wait_until_succeeds("grep survived /home/alice/after", timeout=60)
        client.wait_until_succeeds("grep -a 'COMMAND_EXIT_CODE=.0' /tmp/out", timeout=60)

    with subtest("a forwarded connection survives a restart of the service"):
        server.succeed(
            "(runuser -u alice -- socat -t 60 UNIX-LISTEN:/home/alice/echo.sock EXEC:cat"
            " >/dev/null 2>&1 &)"
        )
        client.succeed("(qsh -N -L /tmp/echo.sock:/home/alice/echo.sock alice@server >/dev/null 2>&1 &)")
        client.wait_until_succeeds("test -S /tmp/echo.sock", timeout=30)
        client.succeed(
            "((echo before; sleep 5; echo after) | socat -t 60 - UNIX-CONNECT:/tmp/echo.sock"
            " > /tmp/echoed 2>&1 &)"
        )
        client.wait_until_succeeds("grep before /tmp/echoed", timeout=30)
        server.succeed("systemctl restart qshd.service")
        server.wait_for_unit("qshd.service")
        client.wait_until_succeeds("grep after /tmp/echoed", timeout=60)
  '';
}
