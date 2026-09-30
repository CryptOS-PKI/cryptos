# Audit log

A node records every call to its gRPC API in a hash-chained audit log on its
encrypted state partition: who called, which call, when, and whether it
succeeded. Each entry is signed with a key derived for the audit log alone and
carries the SHA-256 of the entry before it, so an entry that is changed or
removed after it was written breaks the chain.

`cryptosctl audit list` reads the log and `cryptosctl audit verify` checks the
chain. Both need the bootstrap admin client certificate over mTLS (or the
on-box socket), the same as `ca list-issued`, and both calls are themselves
recorded in the log.

> [!NOTE]
> `cryptosctl` runs on Linux and macOS today. A Windows build is coming.

## What an entry holds

| Field | Meaning |
|---|---|
| seq | The entry's position in the chain, starting at 1 with no gaps. |
| time | When the call was recorded, in UTC. |
| actor | The subject of the caller's client certificate. Empty for the on-box socket, which `audit list` shows as `(local socket)`. |
| event | The call, for example `StartCeremony`, `IssueLeaf`, `RevokeCertificate`, `ApplyConfig`, `ExportCAKey` or `Reboot`. |
| outcome | `ok`, `denied` (the caller wasn't authorized) or `error`. |
| details | Facts a reader needs to see in the clear, such as the serial a revocation named or the DNS names asserted on `IssueLeaf`. The request itself is kept only as a SHA-256 digest. |

`audit list` adds a one-line summary, such as `revoked a certificate: 1a2b`,
and the entry's own SHA-256 in `-o json` and `-o yaml`. They are worked out on
read and aren't part of the chain.

> [!CAUTION]
> The log records API calls only. A reboot from the power button, the
> console's Ctrl+Alt+Delete or a hypervisor hard reset isn't an API call and
> leaves no entry; `cryptosctl reboot` does.

## List entries

```sh
cryptosctl --endpoint pki-issuing.example:443 audit list
```

This prints one page, oldest first, with the sequence number, time, actor,
event, outcome and summary of each entry. When there are more, the last line
gives the `--page-token` for the next page; `--all` fetches every page.

| Flag | Meaning |
|---|---|
| `--since` | Entries at or after this time: RFC3339 (`2026-06-03T12:00:00Z`) or a duration back from now (`24h`). |
| `--until` | Entries before this time, in the same forms. |
| `--type` | One call, by name (`RevokeCertificate`) or full method (`/cryptos.v1.NodeService/RevokeCertificate`). |
| `--actor` | Entries whose actor subject contains this text. Case-sensitive. |
| `--page-size` | Entries per page. The node's default is 100 and it caps a page at 1000. |
| `--page-token` | Continue from a previous page. Use the same filters. |
| `--all` | Fetch every page. |

For example, the revocations one operator made in the last week:

```sh
cryptosctl --endpoint pki-issuing.example:443 audit list \
  --type RevokeCertificate --actor "CN=operator-a" --since 168h
```

> [!CAUTION]
> A page token belongs to the filters it was printed with. Changing a filter
> and keeping the token is refused; start again without it.

`-o json` or `-o yaml` gives the entries as the node stored them, with
`entry_sha256`, `target` and `summary`.

## Verify the chain

```sh
cryptosctl --endpoint pki-issuing.example:443 audit verify
```

The node walks the whole log and checks every entry's signature, that the
sequence numbers run from 1 with no gaps, and that each entry carries the hash
of the one before it.

> [!TIP]
> An intact log prints:
>
> ```text
> audit chain intact: 1284 entries verified
> ```

> [!WARNING]
> A broken chain means an entry was changed, removed or corrupted after it was
> written. `audit verify` prints where it broke and exits non-zero:
>
> ```text
> audit chain broken at seq 812 of 1284 entries: 2026-06-03.log:40: signature mismatch
> ```
>
> The sequence number is the one the failing entry holds, or the one expected
> at its place when the entry can't be read. Nothing is repaired: the node keeps
> appending new entries after the break. Keep the node running and read the
> entries around that sequence with `audit list` before you change anything.

`-o json` and `-o yaml` give `entry_count`, `intact`, `first_broken_sequence`
and `reason`, and the command still exits non-zero on a broken chain, so a
script can check either.
