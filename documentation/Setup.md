# Setup

## Quick start

Put RBProxy in front of an app running on port 3000:

```sh
rbproxy host --target http://127.0.0.1:3000 --listen :8080
```

Start in **monitor** mode on a real site for a few days, check `rbproxy report`
for false positives, then switch to `deceive` (the default) or `protect`.

```sh
rbproxy host -t http://127.0.0.1:3000 --mode monitor --admin 127.0.0.1:9090
```

## Commands

| Command | What it does |
|---|---|
| `rbproxy host` | run the proxy |
| `rbproxy settings` | print every option with its default (`--write file`, `--check file`) |
| `rbproxy report` | summarize the event log: top attackers, categories, stolen canaries, captured logins, learned traps, leaks |

## Config file

```sh
rbproxy settings --write rbproxy.json
rbproxy host --config rbproxy.json
```

Main options (durations are strings such as `"90s"`, `"15m"`):

| Key | Default | Meaning |
|---|---|---|
| `sites[]` | | `listen`, `target`, optional `cert`/`key` for HTTPS |
| `mode` | `deceive` | `monitor`, `protect` or `deceive` |
| `event_log` | `rbproxy-events.jsonl` | JSON-lines log, `""` to disable |
| `admin.listen` / `admin.token` | | admin API; a token is required unless bound to loopback |
| `trusted_proxies` | `[]` | CIDRs whose `X-Forwarded-For` is believed (your CDN / load balancer) |
| `preserve_host` | `false` | send the client's `Host` to the backend instead of the target's |
| `forward_client_info` | `false` | add `X-RBProxy-Client/Score/Action` headers for the backend |
| `block_finding_score` | `8` | a single payload this strong is never forwarded |
| `leaks.detect` / `leaks.redact` | `true` / `false` | scan responses for secrets / replace them |
| `profile.*` | | window, rate limit, watch/block scores, block duration, blacklist, half-life |
| `honeypot.*` | | enable, tarpit, learn threshold, password logging, canary TTL |

## Behind a CDN or load balancer

Without `trusted_proxies`, every request seems to come from the CDN and one
attacker would get the whole CDN blocked. List the CDN's ranges:

```json
"trusted_proxies": ["10.0.0.0/8", "173.245.48.0/20"]
```

## Admin API

```sh
curl 127.0.0.1:9090/api/stats
curl '127.0.0.1:9090/api/clients?min_score=15'
curl 127.0.0.1:9090/api/clients/203.0.113.7
curl -X POST '127.0.0.1:9090/api/clients/203.0.113.7/block?minutes=0'   # blacklist
curl -X POST 127.0.0.1:9090/api/clients/203.0.113.7/unblock
curl '127.0.0.1:9090/api/events?n=50&min_severity=high'
curl 127.0.0.1:9090/api/traps
```

## Event types

`attack`, `pattern` (scanner, enumeration, bruteforce, flood, ua-rotation...),
`honeypot_hit`, `honeypot_created`, `decoy_served`, `credentials_captured`,
`canary_used`, `blocked`, `blacklisted`, `denied`, `leak`, `manual_block`,
`manual_unblock`.
