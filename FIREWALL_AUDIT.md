# Firewall Principles Audit — NetworkMonitor

**Audit date:** 2026-02-28
**Branch:** `claude/scan-firewall-principles-VKwkf`
**Scope:** Full repository scan — all Python services, sensors, Docker Compose, ksqlDB, Suricata config

---

## Executive Summary

The platform has a **strong detection and analysis layer** (Suricata IDS, Zeek DPI, AI triage) but the **enforcement layer** (`soar_blocker`) was missing several foundational firewall principles. Five gaps were critical enough to implement immediately; the remaining are documented for follow-up.

---

## Principles Implemented (this PR)

### 1. IP Format Validation ✅ (was: ❌ missing)

**File:** `services/soar_blocker/soar_blocker.py` — `validate_ip()`

**Problem:** `src_ip` arrived from a Kafka message (untrusted external data) and was interpolated directly into a shell command string with no format check:
```python
cmd = blocklist_cmd.format(ip=src_ip)   # src_ip could be "1.2.3.4; rm -rf /"
subprocess.run(cmd, shell=True, check=True)  # executes the injection
```

**Fix:** `ipaddress.ip_address(ip)` parse is applied before any further processing. Invalid values are logged and dropped. Valid IPv4/IPv6 addresses contain only `[0-9a-fA-F:.]` — no shell metacharacters. `shlex.split()` + `shell=False` is then used for subprocess calls as defense-in-depth.

---

### 2. Allowlisting — Private IP Protection ✅ (was: ❌ missing)

**File:** `services/soar_blocker/soar_blocker.py` — `is_private_ip()`, `_PRIVATE_NETS`

**Problem:** When `LLM_BLOCK_ENABLED=false` (the default), the LLM prompt that "considered" RFC1918 addresses was bypassed entirely. An internal host that triggered a high-severity Suricata alert would be blocked by automated iptables rules, cutting off legitimate internal traffic.

**Fix:** Hard-coded `_PRIVATE_NETS` list covers RFC1918, loopback, link-local, and IPv6 private ranges. These are **never blocked** unless the operator explicitly sets `BLOCK_PRIVATE_IPS=true`.

**Ranges protected by default:**
| Range | Description |
|-------|-------------|
| `10.0.0.0/8` | RFC1918 Class A |
| `172.16.0.0/12` | RFC1918 Class B |
| `192.168.0.0/16` | RFC1918 Class C |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `::1/128` | IPv6 loopback |
| `fc00::/7` | IPv6 ULA |
| `fe80::/10` | IPv6 link-local |

---

### 3. Allowlisting — Trusted IP List ✅ (was: ❌ missing)

**File:** `services/soar_blocker/soar_blocker.py` — `build_trusted_set()`, `is_trusted_ip()`

**Problem:** No mechanism to protect known-good external IPs (monitoring probes, partner networks, CDN ranges, admin VPN exit nodes) from being auto-blocked.

**Fix:** New `TRUSTED_IPS` env var accepts a comma-separated list of IPs and/or CIDRs. Entries are validated on startup; invalid entries are logged and skipped. Trusted IPs are checked before LLM consultation and before any block action.

**Example docker-compose config:**
```yaml
TRUSTED_IPS: "203.0.113.10,198.51.100.0/24,2001:db8::/32"
```

---

### 4. Block TTL / Automatic Unblocking ✅ (was: ❌ missing)

**File:** `services/soar_blocker/soar_blocker.py` — `schedule_unblock()`, `is_block_active()`

**Problem:** The `blocked` set grew forever and iptables rules were permanent. False positives had no recovery path without manual intervention. A mis-identified IP stayed blocked indefinitely.

**Fix:** Two new env vars:

| Variable | Default | Description |
|----------|---------|-------------|
| `BLOCK_TTL_SECONDS` | `0` (permanent) | Seconds before the block is automatically removed |
| `BLOCKLIST_UNBLOCK_CMD` | _(empty)_ | Shell command to remove the block rule |

When `BLOCK_TTL_SECONDS > 0`, a daemon `threading.Timer` fires the unblock command after the TTL expires and removes the IP from the in-memory `blocked` set so it can be re-evaluated.

**Example:**
```yaml
BLOCKLIST_CMD: "iptables -A INPUT -s {ip} -j DROP"
BLOCK_TTL_SECONDS: "3600"
BLOCKLIST_UNBLOCK_CMD: "iptables -D INPUT -s {ip} -j DROP"
```

---

### 5. Egress Filtering ✅ (was: ❌ missing)

**File:** `services/soar_blocker/soar_blocker.py` — `execute_block()`, `BLOCKLIST_EGRESS_CMD`

**Problem:** Only the `INPUT` chain was blocked. A compromised internal host connecting **out** to a malicious C2 IP, or an attacker IP receiving exfiltrated data, were not covered by outbound rules.

**Fix:** New `BLOCKLIST_EGRESS_CMD` env var. When set, it is executed alongside the ingress block. Failures are logged as warnings (not errors) so a failed egress rule doesn't suppress the ingress block.

**Example:**
```yaml
BLOCKLIST_CMD: "iptables -A INPUT -s {ip} -j DROP"
BLOCKLIST_EGRESS_CMD: "iptables -A OUTPUT -d {ip} -j DROP"
```

---

### 6. Alert Rate Limiting ✅ (was: ❌ missing)

**File:** `services/soar_blocker/soar_blocker.py` — `alert_rate_check()`

**Problem:** A single IDS alert immediately triggered a block. Noisy Suricata signatures (e.g., generic TLS fingerprint matches) could cause wide-scale false-positive blocking from a brief traffic burst.

**Fix:** Two new env vars:

| Variable | Default | Description |
|----------|---------|-------------|
| `MIN_ALERTS_TO_BLOCK` | `1` (original behaviour) | Minimum alert count before blocking |
| `ALERT_WINDOW_SECONDS` | `60` | Time window for alert accumulation |

The counter resets when the window expires. Setting `MIN_ALERTS_TO_BLOCK=3` means three qualifying alerts within 60 seconds are required before a block is committed.

---

## New Environment Variables Reference

Add to `docker-compose.yml` → `soar_blocker.environment`:

```yaml
# Allowlisting
BLOCK_PRIVATE_IPS: "false"          # set true ONLY in fully-routed lab environments
TRUSTED_IPS: ""                     # comma-separated IPs/CIDRs, never blocked

# Egress filtering
BLOCKLIST_EGRESS_CMD: ""            # e.g. "iptables -A OUTPUT -d {ip} -j DROP"

# Block TTL / auto-unblock
BLOCK_TTL_SECONDS: "0"              # 0 = permanent; set to e.g. 3600 for 1-hour TTL
BLOCKLIST_UNBLOCK_CMD: ""           # e.g. "iptables -D INPUT -s {ip} -j DROP"

# Alert rate limiting
MIN_ALERTS_TO_BLOCK: "1"            # raise to 3-5 to reduce false positives
ALERT_WINDOW_SECONDS: "60"          # window for alert accumulation
```

---

## Remaining Gaps (Not Implemented — Require Architecture Decisions)

### Stateful Connection Tracking ⚠️

**Gap:** iptables rules are stateless append operations. Established connections from a freshly-blocked IP may continue through conntrack until they time out.

**Recommendation:** Use `-m conntrack --ctstate NEW` in `BLOCKLIST_CMD`, or switch to `nftables` with proper set-based rules for atomic, stateful blocking.

---

### Port-Level / Service-Level Granularity ⚠️

**Gap:** All blocks are full-IP drops. An IP triggering a port-scan alert gets blocked from all services, including those it was legitimately using.

**Recommendation:** Extend the alert schema to carry `dst_port` and construct port-specific rules:
```
iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP
```

---

### Geo-Based Blocking ⚠️

**Gap:** `geoip_enricher` adds country data to every event, but `soar_blocker` ignores it. Country-level blocking policies (e.g., drop all traffic from specific regions) are not enforced.

**Recommendation:** Add `BLOCKED_COUNTRIES` env var; check `val.get("country_code")` in the alert pipeline and apply blocks before severity checks.

---

### Kafka Transport Encryption ⚠️

**Gap:** All Kafka listeners use `PLAINTEXT` (see `docker-compose.yml` line 20-21). Security alerts, block actions, and anomaly scores flow in the clear on the internal Docker network.

**Recommendation:** Enable `SSL` or `SASL_SSL` listeners. At minimum, add network-level encryption (WireGuard, TLS sidecar) for inter-container communication in production.

---

### Hardcoded Credentials ⚠️

**Gap:** `docker-compose.yml` contains:
```yaml
NEO4J_AUTH: neo4j/neo4jpassword
NEO4J_PASSWORD: "neo4jpassword"
```
These appear in plaintext across multiple services.

**Recommendation:** Move all credentials to `.env` file (already present as `.env.example`), use Docker secrets, or a secrets manager. The `.env` file is already in `.gitignore`.

---

### Network Segmentation ⚠️

**Gap:** All containers share a flat Docker bridge network. A compromised container can reach any service (Kafka, Neo4j, Ollama) without restriction.

**Recommendation:** Define explicit Docker networks per tier (sensor-net, processing-net, storage-net) in `docker-compose.yml` and restrict cross-tier access with network policies.

---

### Permanent Block Persistence ⚠️

**Gap:** The `blocked` set is in-memory only. A container restart clears all blocks, and iptables rules added by the previous instance may or may not persist depending on the host's iptables-persistent configuration.

**Recommendation:** Persist the active block list to a file or Redis on change; reload on startup. Alternatively, use ipsets for atomic rule management:
```bash
ipset create blocklist hash:ip timeout 3600
iptables -A INPUT -m set --match-set blocklist src -j DROP
# add entry: ipset add blocklist {ip} timeout 3600
```

---

## Scan Coverage

| File | Principles Checked |
|------|--------------------|
| `services/soar_blocker/soar_blocker.py` | All 6 implemented + all remaining gaps |
| `sensors/ids_alert_forwarder/ids_alert_forwarder.py` | Input validation, topic filtering |
| `sensors/traffic_analysis/traffic_analysis.py` | Egress visibility, flow data integrity |
| `services/packet_launcher/packet_launcher.py` | Auth gating, IP validation, rate limits |
| `services/ai_analyst/ai_analyst.py` | Recommendation mapping, severity thresholds |
| `services/geoip_enricher/geoip_enricher.py` | Geo-blocking potential (unused by blocker) |
| `stream_aggregation/init.sql` | Alert correlation schema |
| `docker-compose.yml` | Network config, credentials, Kafka encryption |
| `sensors/suricata_custom/Dockerfile` | Rule update strategy |
