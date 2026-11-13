# quicsh

An SSH replacement that runs over QUIC.

## Motivation

SSH multiplexes every channel over one TCP connection, so a lost packet stalls
your shell while a file transfer waits for the retransmit. It also needs
several round trips before you can type anything. I looked at MPTCP first, but
that's a lot of kernel and middlebox pain for a transport that would still have
those two problems.

QUIC gives each channel its own stream, finishes the handshake in one round
trip, and carries TLS 1.3. quicsh puts the parts of SSH I use every day on top
of it, and keeps the things that already work.

It's young and nobody has audited it. Don't put it on a machine you can't
afford to lose :)

## What works

- Login shells and remote commands, with a terminal or with pipes
- `-L`, `-R` and `-D` (SOCKS5) forwarding
- Agent forwarding with `-A`, which keeps working after a reattach
- `rsync -e qsh`, and `scp` and `sftp` with `-S qsh`
- Jump hosts with `-J` or `ProxyJump`, as many as you chain. A jump host
  runs `qshd` and only ever sees encrypted packets
- IPv4 and IPv6 on one socket
- Roaming. A session carries on when the client changes networks
- Reattaching. A terminal session survives up to an hour without a
  connection, and `qsh` picks it up again. The server keeps the last 256 KiB
  of output for that, and `qsh` says so when more was produced
- Restarting `qshd` under a terminal session. The session lives in a process
  of its own, and `qsh` reattaches with the next packet it sends, a keystroke
  or the keep-alive that goes out every 15 seconds
- `ed25519`, ECDSA (P-256 and P-384) and RSA keys, signed through `ssh-agent`
  or `ssh-keygen`
- `ed25519-sk` keys in the same way, with the PIN and the touch

## Usage

The server reads the OpenSSH host key and each account's
`~/.ssh/authorized_keys`, so a machine that already runs `sshd` needs no setup.
It listens on UDP port 22, which you'll have to open in your firewall.

```sh
qshd
```

On NixOS the flake has a module for it.

```nix
{
  imports = [ inputs.quicsh.nixosModules.default ];

  services.qshd.enable = true;
}
```

The client takes the flags you'd expect from `ssh`.

```sh
qsh host
qsh user@host uname -a
qsh -t host htop
qsh -A host
qsh -N -L 8080:localhost:80 -D 1080 host
qsh -J bastion host
```

`scp` and `sftp` take `qsh` as their transport. The server runs OpenSSH's
`sftp-server` for them, and `--sftp-server` names it when it lives somewhere
unusual.

```sh
scp -S qsh notes.txt host:
sftp -S qsh host
rsync -a -e qsh src/ host:dst/
```

Keys come from `ssh-agent` when one is running. Without one, `ssh-keygen`
signs with the usual `~/.ssh/id_*` files or the file you pass to `-i`, and it
asks for the passphrase, PIN or touch itself. `qsh` never reads a
private key file either way, so encrypted keys and FIDO keys work the same way
plain ones do. `-i` also picks which agent key to offer, which is worth doing
with security keys since every wrong one costs you a touch.

`qsh` reads `~/.ssh/config` and `/etc/ssh/ssh_config` for `HostName`, `User`,
`IdentityFile` and `ProxyJump`, so the names you already use with `ssh` work.
`Port` is ignored, because that's sshd's TCP port and `qshd` may sit on
another one. `QshPort` sets the UDP port, and `IgnoreUnknown` makes `ssh` skip
it.

```
IgnoreUnknown QshPort

Host box
   QshPort 4222
```

Accounts come from `/etc/passwd`, and from `getent` for the ones that live in
LDAP or `systemd-homed`.

Host keys are checked against `~/.ssh/known_hosts` first. Keys you accept at
the prompt are written to `~/.ssh/known_hosts_quicsh`, and your OpenSSH file is
never modified.

## Design

`qshd` is two processes. The one that runs QUIC and TLS and parses everything a
client sends has no privileges and never sees the host key. The other keeps
root and the host key, and it only ever answers a small set of requests over
a socket pair. It signs TLS handshake transcripts and nothing else, it checks
logins itself, and it starts sessions only for accounts that logged in. If
someone finds a parsing bug, they get a process running as `sshd` that can't
sign anything or become anyone.

That process does hold one secret, a random value that lets a restarted
server tell old clients their connection is gone. Whoever steals it can cut
connections they can observe until the next reboot, and that's all it's good
for.

A few `authorized_keys` options lean on that unprivileged process. `from=` is
checked by the root half against the client address the other half reports,
and `no-port-forwarding`, `permitopen=` and `permitlisten=` are enforced where
forwarded connections are opened. Someone who took over the network process
could get around those, though they'd still need the private key to log in.

Each terminal session gets a third process that runs as the account, owns the
terminal and keeps recent output. The server talks to it over a socket in a
directory only root can enter, which is how a session outlives both a lost
connection and a restarted server.

Login doesn't use TLS client certificates. The client signs a value derived
from the TLS handshake with its SSH key and sends that on the first stream. A
signature is only good for one connection to one host key, and it uses the
same format as `ssh-keygen -Y sign` under its own namespace, so it can't be
replayed as an OpenSSH login or the other way around. This is also why FIDO
keys work, since they can't sign a TLS handshake directly.

The key exchange is X25519MLKEM768, the hybrid of X25519 and ML-KEM-768 that
browsers ship. Someone who records a session today can't decrypt it later
unless both of them fall. Host keys and logins still use classical
signatures, so this covers recorded traffic and not a forged login.

A jump is a second `qsh` that logs in to the jump host and asks it to relay
UDP to the next server. The real connection runs through that relay from end
to end, so the jump host can drop your packets and can't read them. The two
`qsh` processes share a socket pair, which nothing else on your machine can
reach.

Each client gets its own UDP socket on the server. Without that, one client's
bulk transfer sits in the same kernel queue as another client's keystrokes.
The send window is sized from the measured round trip time for the same
reason, since a big window lets megabytes of file data queue up in front of a
single character.

The transport is `quinn-proto` and `quinn-udp` on a small single-threaded
event loop. There is no async runtime and no unsafe code in this crate.

## Performance

These came from `qsh` and OpenSSH 10.6 on one loaded machine, over loopback
with `netem` adding delay and loss, so treat them as rough.

- At 50 ms of round trip time, running `true` on the server takes 246 ms
  from start to finish. OpenSSH takes 693 ms.
- At 50 ms and 1% packet loss, a bulk upload runs at 1.3 Gbit/s. OpenSSH
  manages 0.2.
- On a clean path with a 1500 byte MTU, an upload moves about 4.4 Gbit/s per
  core, counting both ends. OpenSSH moves about 3.6.

So it's a lot better on a slow or lossy network and about even on a clean
one. Loopback is kind to QUIC though, since the kernel never has to split a
batch into real packets there, and I haven't measured it between two machines.

## What's missing

- Passwords and PAM. Keys only.
- X11 forwarding.
- Most of `ssh_config`. Only `Host`, `Match all`, `Include`, `HostName`,
  `User`, `IdentityFile`, `ProxyJump` and `QshPort` are read.
- P-521 keys, RSA keys under 2048 bits and RSA signatures over SHA-1.
  `ecdsa-sk` keys are accepted but nobody has tried one.
- Host keys other than `ed25519`.
- A few `authorized_keys` options. `command=`, `from=`, `expiry-time=`,
  `permitopen=`, `permitlisten=`, `restrict`, `no-touch-required`,
  `verify-required` and the `pty`, `agent-forwarding` and `port-forwarding`
  switches are enforced. `environment=` is ignored, as `sshd` does by default.
  A line with any other option, such as `cert-authority` or `tunnel=`, is
  skipped instead of being honored without its restriction. `from=` matches
  addresses and networks and never host names. An `expiry-time=` without a
  `Z` ends up to a day early, since `qshd` doesn't know your time zone.
- Restarts for anything but terminal sessions. Remote commands on pipes and
  open forwarded connections end with the server.
- Anything but Linux.

## Building

```sh
nix build
```

Or with a nightly toolchain,

```sh
cargo build --release
```

`nix develop` gives you that toolchain.

## License

<!--markdownlint-disable MD033 MD059-->

[provided here]: https://interoperable-europe.ec.europa.eu/sites/default/files/custom-page/attachment/eupl_v1.2_en.pdf

This project is made available under European Union Public Licence (EUPL)
version 1.2. See [LICENSE](LICENSE) for more details on the exact conditions. An
online copy is [provided here].

<!--markdownlint-enable MD033 MD059-->
