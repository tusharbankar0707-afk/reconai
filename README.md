# ReconAI

AI-assisted external reconnaissance and attack-surface assessment for defensive security teams.

## Responsible use
ReconAI is for **authorized** reconnaissance, learning, and defensive assessment only. Scan
only domains you own or have explicit written permission to test. The tool performs passive
DNS/WHOIS lookups, a bounded subdomain check (8 names), and a single HTTP/TLS fingerprint per scan.

## Architecture
Flask UI and JSON API → `scan_engine` (background workers) → recon modules (DNS, WHOIS,
HTTP/TLS, tech) → `ai_analyzer` (rule-based score + LLM report with deterministic fallback)
→ SQLite via `repository`. Reports export as JSON or Markdown.

## Security controls
- Strict hostname validation; URLs are reduced to a bare domain; IP literals are refused.
- Non-public resolutions are refused unless `ALLOW_PRIVATE_TARGETS=true`.
- No shell execution anywhere.
- Per-module timeouts, bounded response bodies, bounded subdomain concurrency.
- Scan creation requires an explicit authorization confirmation and is rate-limited.
- LLM receives recon data marked as untrusted, is asked for defensive output only, and its
  score is blended with the rule score to limit drift.

## Known limitations
- The private-address check runs on DNS results; a DNS-rebinding race between that check and
  the HTTP request is possible. Run the app in an egress-restricted network for stronger guarantees.
- Rate limiting is in-process. Use a shared store (e.g. Redis) and a reverse proxy for multi-instance deployments.
