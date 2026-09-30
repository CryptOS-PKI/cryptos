# Time sync

A CA's clock sets the notBefore and notAfter of every certificate, the CRL's
thisUpdate and nextUpdate, OCSP response times and audit times. A node keeps its
clock in sync with a small client-only SNTPv4 (RFC 4330, and RFC 5905 section
14) built into init. It never serves time.

## Configure the servers

```yaml
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
  nameservers: [10.0.0.53]
  ntp_servers: [10.0.0.123, time.example.org]   # at most 3, IPv4 literals or hostnames
```

A hostname is resolved through the node's resolver at every poll, so a DNS change
takes effect without a reboot. `cryptosctl config apply` warns when a hostname
is listed and `nameservers` is empty: the node then resolves it only if its DHCP
lease supplies DNS servers.

With `ntp_servers` empty the node uses the NTP servers from its kernel DHCP
lease (option 42), if it got any. With neither, the node runs on its hardware
clock, and `config apply` warns about it. That is the expected setup for an
offline Root.

## What the node does

- **At boot**, after the network and resolver are up and before etcd, the
  listeners and signing start, the node queries every server, retrying an
  unanswered one up to three times 2 seconds apart. It gives up after about
  10 seconds and boots anyway. An offset above 128 ms is stepped; a smaller one
  is slewed.
- **After boot** it polls each server every 64 seconds, backing off to 1024
  seconds while a server does not answer. Small offsets are slewed. A forward
  offset above 128 ms is stepped. A backward one is refused and logged as an
  error, because it would reorder audit and issuance times on a running CA.
- **Several servers:** the node takes the median offset. If two or more servers
  answered and their offsets are more than 1 second apart, it adjusts nothing
  and reports `sources disagree`. The 3-server limit and the 1-second window are
  fixed.
- **Replies** are checked as RFC 4330 and RFC 5905 require. The request carries a
  random transmit timestamp that the reply must echo, and the socket only takes
  replies from the server it asked. A server that sends a kiss-o'-death `DENY` or
  `RSTR` is not queried again until reboot; `RATE` halves how often it is polled.
- **The clock floor:** the clock is never stepped behind the latest of the image
  build time, the last good sync, and the latest notBefore the node has issued.
  The floor is kept on the encrypted state volume. A server whose time is behind
  it is refused and logged as an error.

The time is not authenticated (no NTS). The random nonce, the median and
agreement rule, the floor, and the forward-only rule after boot limit what one
bad or spoofed server can do.

## The signing gate

While a time source is configured or leased but the clock has not synced yet
this boot, the node refuses to sign certificates: subordinate CA signing and
every leaf path, including ACME, EST and SCEP. The call fails with
`FailedPrecondition` before the CA key is loaded. The gate opens at the first
good sync and stays open for the rest of the boot, even if a later poll fails.

- A node with **no time source** is never gated.
- **CRL and OCSP** are never gated. A stale-looking CRL is better than none.
- The node's own **service certificates** are not gated either: the OCSP
  responder, the EST server and the SCEP RA certificates are minted when their
  listeners start, often before a first sync, so those listeners can come up.
- `pki.allow_unsynced_clock: true` lifts the gate. Every certificate signed that
  way is logged as a warning. Leave it off in production.

```yaml
pki:
  allow_unsynced_clock: true   # sign on an unsynced clock (lab only)
```

## Status

`cryptosctl status` prints a `Clock:` line: the state, the source and servers,
then the server, offset, stratum and time of the latest good sync, or why the
latest attempt did not adjust the clock.

```text
Clock:           SYNCED MACHINE_CONFIG 10.0.0.123, time.example.org (via time.example.org, offset -12.5ms, stratum 2, synced 2026-09-29T12:00:00Z, stepped at boot)
Clock:           UNSYNCED DHCP_LEASE 192.0.2.123: timesync: sources disagree: offsets spread 4.9s across 2 servers (more than 1s)
Clock:           NOT_CONFIGURED (no time source; running on the hardware clock)
```

The states are `NOT_CONFIGURED`, `PENDING` (configured, no sync finished yet),
`SYNCED` and `UNSYNCED`. The same fields are in `GetStatus` as `time_sync`.
