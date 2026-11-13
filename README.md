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
- Agent forwarding with `-A`
- IPv4 and IPv6 on one socket
- Roaming. A session carries on when the client changes networks
- Reattaching. A terminal session survives up to an hour without a
  connection, and `qsh` picks it up again without losing output
- `ed25519` keys, signed through `ssh-agent`
- `ed25519-sk` keys in the same way, though I haven't tried one against real
  hardware yet

## Usage

The server reads the OpenSSH host key and each account's
`~/.ssh/authorized_keys`, so a machine that already runs `sshd` needs no setup.
It listens on UDP port 22, which you'll have to open in your firewall.

```sh
qshd
```

The client takes the flags you'd expect from `ssh`.

```sh
qsh host
qsh user@host uname -a
qsh -t host htop
qsh -A host
qsh -N -L 8080:localhost:80 -D 1080 host
```

Keys come from `ssh-agent` only. `qsh` never reads a private key file, so
encrypted keys and FIDO keys work the same way plain ones do. `-i` takes a
public key file and picks which agent key to offer, which is worth doing with
security keys since every wrong one costs you a touch.

Host keys are checked against `~/.ssh/known_hosts` first. Keys you accept at
the prompt are written to `~/.ssh/known_hosts_quicsh`, and your OpenSSH file is
never modified.

## Design

`qshd` is two processes. The one that runs QUIC and TLS and parses everything a
client sends has no privileges and holds no secrets. The other keeps root and
the host key, and it only ever answers a small set of requests over a socket
pair. It signs TLS handshake transcripts and nothing else, it checks logins
itself, and it starts sessions only for accounts that logged in. If someone
finds a parsing bug, they get a process running as `sshd` that can't sign
anything or become anyone.

Login doesn't use TLS client certificates. The client signs a value derived
from the TLS handshake with its SSH key and sends that on the first stream. A
signature is only good for one connection to one host key, and it uses the
same format as `ssh-keygen -Y sign` under its own namespace, so it can't be
replayed as an OpenSSH login or the other way around. This is also why FIDO
keys work, since they can't sign a TLS handshake directly.

Each client gets its own UDP socket on the server. Without that, one client's
bulk transfer sits in the same kernel queue as another client's keystrokes.
The send window is sized from the measured round trip time for the same
reason, since a big window lets megabytes of file data queue up in front of a
single character.

The transport is `quinn-proto` and `quinn-udp` on a small single-threaded
event loop. There is no async runtime and no unsafe code in this crate.

## Performance

These came from a loopback benchmark with `netem` adding delay and loss, on
one machine, so treat them as rough.

- At 50 ms of round trip time, connecting takes 103 ms. OpenSSH takes 648 ms.
- At 1% packet loss, bulk transfer runs at 1.3 Gbit/s. OpenSSH manages 0.2.
- On a clean path with a 1500 byte MTU, OpenSSH is about 1.6x faster per core.
  QUIC pays per packet and TCP gets segmentation offload for free. With jumbo
  frames it goes the other way.

So it's better on real networks and worse between two machines on the same
switch. I'd like to close that gap, but it isn't closed.

## What's missing

- Passwords and PAM. Keys only.
- X11 forwarding and the `sftp` subsystem.
- `ssh_config`. Hosts, ports and users go on the command line.
- Key types other than `ed25519` and `ed25519-sk`.
- `authorized_keys` options. A line with `command=` or `from=` is skipped
  instead of being honored without its restriction.
- Accounts that only exist in LDAP or another NSS source. Lookups read
  `/etc/passwd`.
- A post-quantum key exchange. This is planned.
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
