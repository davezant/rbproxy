# RBProxy

RBProxy is a reverse proxy made for catching "script kiddies" while monitoring every request and response for the server. The project is not meant to make the developer ignore bugs, but to make them less bad than they already are.

It aims to excel at:

- **Port adaptability**: any number of listeners (HTTP or HTTPS), each in front of its own backend.
- **Fake exploits to reach malicious people**: honeypots that look like the files and panels attackers hunt for.
- **Detecting attacks and leaks**: payloads in requests, secrets and stack traces in responses.
- **Reporting** attacks, injection attempts and exploits, with a simulated answer so the attacker keeps talking.

## How a request flows

```
client ──► 1. blocked?  ──yes──► 403 (nothing parsed, nothing scanned)
             │ no
             ▼
           2. profile   rate, scanner user agents, login bursts, UA rotation
           3. canaries  is this request using credentials a honeypot handed out?
           4. payloads  45 scored rules: sqli, xss, cmdi, traversal, ssti,
                        nosqli, crlf, code, jndi (Log4Shell), xxe, ssrf
           5. traps     /.env, /.git, /wp-login.php, phpMyAdmin, dumps, learned paths
           6. decide    allow · watch · throttle · block (escalates to blacklist)
             │
             ├── shadow trap ───────────► decoy (backend never sees it)
             ├── strong payload ────────► fake "success" (deceive) or 403 (protect)
             ▼
           backend ──► 404? ──► decoy if the path is a trap or the client is suspicious
                   └─► body checked for leaked secrets (optionally redacted)
```

## Scores

Every client (an IPv4 address, or an IPv6 /64) has a threat score. Payloads,
trap hits and behavioural patterns add to it; it halves every 10 minutes.

| Score | Action |
|---|---|
| < 15 | allow |
| ≥ 15 | **watch**: any payload is answered with a decoy, 404s become honeypots |
| over the rate limit | **throttle** (429) |
| ≥ 60 | **block** for 15 min, doubling each time; the 3rd block is a permanent blacklist |

Some reference weights: known scanner user agent 20, 404 enumeration 12,
brute force 15, `UNION SELECT` 9, `/.env` 12, reusing a canary 50.

## Honeypots

- **Built-in traps**: paths nobody legitimate asks for. *Shadow* traps (`.env`,
  `.git`, `.aws`, `.ssh`, config backups, webshells) are never forwarded, so a
  real leaked file is never served. The others (`/wp-login.php`, `/admin`,
  phpMyAdmin, dumps, `/actuator`...) go to the backend first and only become a
  decoy when the backend answers 404. A real `/admin` keeps working.
- **Spontaneous decoys**: a suspicious client that hits a 404 gets something
  plausible for that path instead: a directory listing that links to more
  traps, a config file, a valid zip with a SQL dump inside.
- **Learned traps**: when 3 different suspicious clients probe the same missing
  path, it becomes a permanent trap.
- **Canaries**: every credential in a decoy is generated for that one client.
  When it comes back, from any IP, the event says who stole it and both
  identities are linked.
- **Credential capture**: logins typed into fake panels are logged (passwords
  masked unless `honeypot.log_passwords` is on).
- **Tarpit**: decoys are answered slowly (0.3–1.5 s) to waste scanners' time.
