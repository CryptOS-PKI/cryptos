# Trusting a node's management certificate

Every remote `cryptosctl` call is mutual TLS. The client proves itself with
`--identity` and `--identity-key`, and it checks the node's certificate against
`--trust` (default `~/.cryptos/trust.crt`). This page covers `--trust`: what
it has to contain, how to get it, and why it goes stale.

## What the node presents

The management listener (port 443) does **not** present a certificate from
the node's CA. At every boot the node generates a new key and a new
**self-signed** certificate for it. That certificate:

- is issued by itself, so it chains to nothing. Your root does not verify it,
  and neither does the node's own CA certificate or any other bundle.
- names two subjects: the IP address from the node's `network.address`, and
  `localhost`. It carries no DNS names.
- is replaced on the next boot. The key, serial and fingerprint all change.

So `--trust` has to be **the node's current management certificate itself**,
pinned. Pointing it at a CA certificate fails like this:

> [!TIP]
> This output means `--trust` does not hold the node's current management
> certificate:
>
> ```text
> x509: certificate signed by unknown authority
> ```
>
> Fetch the current certificate, as in [Getting the current certificate](#getting-the-current-certificate), then retry.

A pin taken before a reboot fails the same way afterwards. Any reboot does it:
a planned restart, `image activate`, a power event, a hypervisor migration that
restarts the guest.

## Getting the current certificate

Run this after the node has finished booting, and again after every reboot.
Substitute the node's management IP address.

First read the fingerprint off the node itself. On a serving node the console
dashboard shows a **Mgmt SHA-256** line: the SHA-256 of the management
certificate this boot, in groups of four hex digits. It changes on every boot,
like the certificate.

> [!NOTE]
> `cryptosctl` runs on Linux and macOS today. A Windows build is coming.

Then fetch the certificate and check it against that value in one step:

```sh
cryptosctl --endpoint 192.0.2.10:443 --trust node-trust.pem \
  trust fetch --expect-sha256 "2D71 1642 B726 B044 0162 7CA9 FBAC 32F5 C853 0FB1 903C C4DB 0225 8717 921A 4881"
```

`trust fetch` connects to `--endpoint`, reads the certificate the node
presents, and saves it to the `--trust` path (`~/.cryptos/trust.crt` when you
leave `--trust` out, which makes it the default for later calls). It prints the
certificate's subject, issuer, subject alternative names, expiry and SHA-256.
No client certificate is needed: the node sends its certificate before it asks
for yours.

`--expect-sha256` takes the value from the console. Spaces, colons and case are
ignored, so the `AB:CD:...` form openssl prints works too. When the node
presents a certificate with any other fingerprint, `trust fetch` fails and saves
nothing. Without `--expect-sha256` it saves whatever it received and says the
pin is not verified; compare the printed SHA-256 with the console before you
rely on it.

> [!TIP]
> Check that the subject alternative names are the node's IP and `localhost`,
> and that the certificate is self-signed (subject and issuer match). Then pass
> `--trust node-trust.pem` on each call, or fetch straight into the default path.

Without `cryptosctl` at hand, openssl gets the same certificate and
fingerprint:

**Linux / macOS**

```bash
openssl s_client -connect 192.0.2.10:443 -servername 192.0.2.10 </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > node-trust.pem
openssl x509 -in node-trust.pem -noout -subject -issuer -enddate -fingerprint -sha256 -ext subjectAltName
```

**Windows (PowerShell)**

```powershell
'Q' | openssl s_client -connect 192.0.2.10:443 -servername 192.0.2.10 2>$null |
  openssl x509 -outform PEM -out node-trust.pem
openssl x509 -in node-trust.pem -noout -subject -issuer -enddate -fingerprint -sha256 -ext subjectAltName
```

## Address the node by IP

The certificate has no DNS names. Hostname verification only passes when the
name `cryptosctl` checks is the node's IP. Use the IP in `--endpoint`:

```sh
cryptosctl --endpoint 192.0.2.10:443 --trust node-trust.pem status
```

If you have to connect through a DNS name, add `--server-name 192.0.2.10` so
verification checks the IP the certificate names. `localhost` only works on the
node itself.

## What this pin does and does not prove

A fetch checked against the console's **Mgmt SHA-256** is a verified pin: the
certificate you saved is the one the node generated this boot, so later calls
reach your node. Reading the console needs access to it (the physical screen or
the hypervisor console), which is the out-of-band channel the check relies on.

> [!CAUTION]
> A fetch you did not check is trust on first use. The pin tells you that later
> calls reach the same endpoint that answered the fetch. It does not tell you
> that endpoint is your node.

For an unchecked pin, what limits the damage is the mutual TLS. An impostor
that answered the fetch still does not hold your admin key, so it cannot relay
your calls to the real node. At worst it pretends to be the node. For each operation, decide what a
fake answer would cost:

- **Signing** (`ca sign-subordinate`). A fake node cannot make a
  certificate that chains to your root. Verify the result against your root
  offline before you use it (see
  [`vmca-subordination.md`](vmca-subordination.md), step 3). A certificate
  that verifies came from your CA, however the pin was obtained.
- **Anything you send to the node.** This covers `config apply`,
  `ca import-key`, and any other request that carries material you would not
  publish. That material goes to whoever answered the fetch. Take the fetch
  from a host on the node's management network, over a path you control, not
  across a segment you do not trust.
- **Anything the node sends back.** For example, a status or identity response.
  Treat it as unauthenticated unless you can check it independently.

When you are finished, delete `node-trust.pem`, or leave it knowing it stops
matching after the next boot. A stale pin fails closed. It never makes a
connection succeed that should not.
