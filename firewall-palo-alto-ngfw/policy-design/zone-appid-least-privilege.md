# Zone & App-ID Least-Privilege Policy Design

**Classification:** [TEMPLATE]

## Zone model (example)

| Zone | Trust | Examples |
|------|-------|----------|
| `unzoned` | none | Unused |
| `outside` | untrusted | Internet |
| `dmz` | semi | Reverse proxies, mail |
| `inside` | trusted | Users |
| `server` | trusted high | App tiers |
| `mgmt` | restricted | Firewall/Panorama mgmt |

## Design principles

1. Default deny between zones; explicit allows only.
2. Prefer **App-ID** over port-only rules; add service only when App-ID insufficient.
3. User-ID / group-based rules for human access paths.
4. Separate temporary troubleshooting rules with expiry tags.
5. Security profiles on all allow rules (or profile groups).
6. Log at session end (and start for critical denies).

## Anti-patterns

- `any` application + `any` service across trust boundaries
- Overlapping shadow rules
- Unused rules without review owners
