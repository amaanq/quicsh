{
  testers,
  openssh,
  rsync,
  self,
}:
testers.runNixOSTest {
  name = "qshd";

  containers.server = {
    imports = [ self.nixosModules.default ];

    services.qshd = {
      enable = true;
      openFirewall = true;
    };

    users.users.alice.isNormalUser = true;
  };

  containers.client =
    { pkgs, ... }:
    {
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.quicsh
        openssh
        rsync
      ];
    };

  testScript = /* py */ ''
    start_all()
    server.wait_for_unit("qshd.service")
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
  '';
}
