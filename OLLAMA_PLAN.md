# Ollama Automation Plan — NetworkMonitor

## Goal
Replace the basic keyword-fallback chat with a full LLM-driven analysis pipeline.
Ollama runs **continuously in the background** analyzing all Kafka events, not just responding to user questions.

## Recommended Model
**`qwen2.5:7b`** (~5.2-5.5GB) — best structured JSON output + security domain knowledge
```bash
# Update install-ollama.sh to pull this:
ollama pull qwen2.5:7b
```

---

## Phase 1 — Fix `sarah_api` Context Injection (Quick Win)

**Problem**: Current code passes `"Recent alerts: N"` to Ollama — useless context.
**Fix**: Pull actual alert payloads and inject them into the prompt.

**Changes to `services/sarah_api/sarah_api.py`:**
- `get_recent_alerts()` already fetches alerts but they're not passed to `query_ollama()`
- Pass actual alert data as JSON string in the context arg
- Switch to `"format": "json"` mode with `temperature: 0.1`
- Expand system prompt with network topology context
- Add `/api/summary` endpoint for current threat state

---

## Phase 2 — New `ai_analyst` Service (Core Automation)

**New file**: `services/ai_analyst/ai_analyst.py`

A background Kafka consumer that:
1. Subscribes to: `alert.correlated`, `security.alerts`, `dpi.events`, `voip.events`, `netflow`
2. Batches events per 30-second window
3. Sends each batch to Ollama for triage
4. Produces structured results to `ai.analysis` Kafka topic
5. Writes `AIAnalysis` nodes to Neo4j

**Output schema** (published to `ai.analysis`):
```json
{
  "event_id": "uuid",
  "timestamp": "ISO8601",
  "source_topic": "security.alerts",
  "original_event": {...},
  "severity": "critical|high|medium|low|info",
  "confidence": 0.85,
  "threat_type": "port_scan|c2_beacon|data_exfil|brute_force|voip_abuse|unknown",
  "src_ip": "...",
  "summary": "One sentence summary",
  "recommendation": "block|monitor|investigate|ignore",
  "reasoning": "Short explanation"
}
```

**Docker service to add** (`docker-compose.yml`):
```yaml
ai_analyst:
  build:
    context: .
    dockerfile: ./services/ai_analyst/Dockerfile
  container_name: ai_analyst
  extra_hosts:
    - "host.docker.internal:host-gateway"
  environment:
    KAFKA_BOOTSTRAP: "kafka:9092"
    OLLAMA_URL: "http://host.docker.internal:11434"
    OLLAMA_MODEL: "qwen2.5:7b"
    NEO4J_URI: "bolt://neo4j:7687"
    NEO4J_USER: "neo4j"
    NEO4J_PASSWORD: "neo4jpassword"
    BATCH_WINDOW_SECONDS: "30"
    ANALYSIS_TOPICS: "alert.correlated,security.alerts,dpi.events,voip.events"
  depends_on:
    - kafka
    - neo4j
```

---

## Phase 3 — LLM-Assisted SOAR Blocker

**Problem**: Current SOAR blocker blocks based on numeric thresholds only — no reasoning.
**Fix**: Before blocking, ask Ollama "should I block this IP?" with full context.

**Changes to `services/soar_blocker/soar_blocker.py`:**
- Add `OLLAMA_URL` and `OLLAMA_MODEL` env vars
- Before executing `blocklist_cmd`, call Ollama with:
  - The alert that triggered the block
  - The IP's recent activity summary (from `ai.analysis` topic cache)
  - Ask: "Is blocking {ip} warranted? Respond JSON: {block: bool, confidence: float, reason: str}"
- Only block if `block: true` AND `confidence >= 0.8` AND numeric threshold met
- Log the LLM reasoning to `blocklist.actions` topic

**New env vars** (with safe defaults):
```
OLLAMA_URL=http://host.docker.internal:11434
OLLAMA_MODEL=qwen2.5:7b
LLM_BLOCK_CONFIDENCE=0.8   # minimum confidence to auto-block
LLM_BLOCK_ENABLED=false    # off by default, enable consciously
```

---

## Phase 4 — Scheduled Threat Summary

**In `sarah_api` or `ai_analyst`:**
- Every hour, generate a digest of `ai.analysis` events from the last hour
- Prompt: "Summarize the last hour of network security events. Key threats, top offenders, recommended actions."
- Store in Neo4j as `ThreatSummary` node
- Expose via `/api/summary` endpoint
- UI: show last summary in Sarah chat widget on open

---

## Phase 5 — UI Improvements

**`SarahChatWidget.jsx` issues to fix:**
1. Hardcoded `192.168.1.115:5000` → use relative URL `/api/chat` (nginx proxy) or env var at build time
2. Show AI triage badge on alerts (severity color from `ai.analysis`)
3. Add "AI Analyst" status indicator (is Ollama up? which model?)
4. Display hourly summary on widget open

---

## Implementation Order

```
[ ] 1. Expand VM, install Ollama, pull qwen2.5:7b
[ ] 2. Test qwen2.5:7b manually: ollama run qwen2.5:7b
[ ] 3. Phase 1: Fix sarah_api context injection (30 min)
[ ] 4. Phase 2: Build ai_analyst service (2-3 hours)
[ ] 5. Add ai_analyst to docker-compose.yml
[ ] 6. Test end-to-end: alert → Kafka → ai_analyst → ai.analysis
[ ] 7. Phase 3: LLM SOAR (1 hour) - only if Phase 2 working well
[ ] 8. Phase 4: Hourly summaries (1 hour)
[ ] 9. Phase 5: UI updates (1-2 hours)
```

---

## Testing Approach

1. **Unit test Ollama prompt**: `python -c "import requests; r=requests.post('http://localhost:11434/api/generate', json={'model':'qwen2.5:7b','prompt':'Analyze this IDS alert: {src_ip: 10.0.0.1, signature: ET SCAN Masscan detected}. Respond in JSON.','format':'json','stream':False}); print(r.json()['response'])"`

2. **Inject test alert to Kafka**:
   ```bash
   docker exec -it kafka kafka-console-producer --bootstrap-server kafka:9092 --topic security.alerts
   # paste: {"src_ip":"10.0.0.1","dest_ip":"192.168.1.1","alert":{"signature":"ET SCAN Masscan","category":"Recon","severity":2}}
   ```

3. **Verify ai.analysis output**:
   ```bash
   docker exec -it kafka kafka-console-consumer --bootstrap-server kafka:9092 --topic ai.analysis --from-beginning
   ```
