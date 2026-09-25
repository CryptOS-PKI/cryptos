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

```
x509: certificate signed by unknown authority
```

A pin taken before a reboot fails the same way afterwards. Any reboot does it:
a planned restart, `image activate`, a power event, a hypervisor migration that
restarts the guest.

## Getting the current certificate

Run this after the node has finished booting, and again after every reboot.
Substitute the node's management IP address:

```sh
openssl s_client -connect 192.0.2.10:443 -servername 192.0.2.10 </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > node-trust.pem
openssl x509 -in node-trust.pem -noout -subject -enddate -fingerprint -sha256 -ext subjectAltName
```

No client certificate is needed for this. The node sends its certificate before
it asks for yours. Check that the subject alternative names are the node's IP
and `localhost`, and that it is self-signed (subject and issuer match):

```sh
openssl x509 -in node-trust.pem -noout -subject -issuer
```

Then either pass `--trust node-trust.pem` on each call, or copy it over
`~/.cryptos/trust.crt` so it becomes the default.

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

The node does not currently display its management certificate's fingerprint
anywhere, not on the console and not in any RPC. There is nothing out of band
to compare against, so the fetch above is trust on first use. The pin tells you
that later calls reach the same endpoint that answered the fetch. It does not
tell you that endpoint is your node.

What limits the damage is the mutual TLS. An impostor that answered the fetch
still does not hold your admin key, so it cannot relay your calls to the real
node. At worst it pretends to be the node. For each operation, decide what a
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
