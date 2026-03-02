import React, { useState, useEffect, useCallback } from "react";

const SETTINGS_URL = "/api/settings";
const TEST_URL     = "/api/settings/test";

// ── Shared styles ─────────────────────────────────────────────────────────────
const S = {
  overlay: {
    position: "fixed", inset: 0, zIndex: 9000,
    background: "rgba(0,0,0,0.85)",
    backdropFilter: "blur(6px)",
    display: "flex", alignItems: "center", justifyContent: "center",
    fontFamily: "'Share Tech Mono', monospace",
  },
  panel: {
    background: "rgba(0,8,20,0.97)",
    border: "1px solid rgba(0,229,255,0.22)",
    borderRadius: 12,
    width: "min(780px, 96vw)",
    maxHeight: "90vh",
    display: "flex",
    flexDirection: "column",
    boxShadow: "0 0 60px rgba(0,229,255,0.12), 0 24px 80px rgba(0,0,0,0.8)",
    overflow: "hidden",
  },
  header: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "16px 22px",
    borderBottom: "1px solid rgba(0,229,255,0.15)",
    background: "rgba(0,229,255,0.04)",
    flexShrink: 0,
  },
  title: { color: "#00e5ff", fontSize: 15, letterSpacing: 3, fontWeight: 700 },
  closeBtn: {
    background: "none", border: "none", color: "#00e5ff",
    fontSize: 20, cursor: "pointer", padding: "0 4px",
  },
  tabs: {
    display: "flex", gap: 0,
    borderBottom: "1px solid rgba(0,229,255,0.12)",
    flexShrink: 0,
    background: "rgba(0,229,255,0.02)",
  },
  tab: (active) => ({
    padding: "10px 18px", cursor: "pointer", fontSize: 11, letterSpacing: 1.5,
    background: active ? "rgba(0,229,255,0.1)" : "transparent",
    color: active ? "#00e5ff" : "rgba(0,229,255,0.45)",
    borderBottom: active ? "2px solid #00e5ff" : "2px solid transparent",
    border: "none", fontFamily: "'Share Tech Mono', monospace",
    transition: "all 0.15s",
  }),
  body: { overflowY: "auto", padding: "22px", flex: 1 },
  section: { marginBottom: 28 },
  sectionTitle: {
    color: "#00e5ff", fontSize: 10, letterSpacing: 3,
    marginBottom: 14, opacity: 0.7,
  },
  row: { marginBottom: 14 },
  label: {
    display: "block", fontSize: 11, color: "rgba(0,229,255,0.6)",
    marginBottom: 5, letterSpacing: 0.5,
  },
  inputWrap: { position: "relative", display: "flex", gap: 8 },
  input: {
    flex: 1, padding: "9px 12px",
    background: "rgba(0,229,255,0.04)",
    border: "1px solid rgba(0,229,255,0.18)",
    borderRadius: 6, color: "#e8e8e8", fontSize: 12,
    fontFamily: "monospace", outline: "none",
    transition: "border-color 0.15s",
  },
  revealBtn: {
    padding: "0 10px",
    background: "rgba(0,229,255,0.08)",
    border: "1px solid rgba(0,229,255,0.18)",
    borderRadius: 6, color: "#00e5ff", cursor: "pointer", fontSize: 13,
  },
  testBtn: (ok) => ({
    padding: "6px 12px", fontSize: 10, letterSpacing: 1,
    background: ok === true ? "rgba(0,230,118,0.15)"
               : ok === false ? "rgba(229,57,53,0.15)" : "rgba(0,229,255,0.08)",
    border: `1px solid ${ok === true ? "rgba(0,230,118,0.4)" : ok === false ? "rgba(229,57,53,0.4)" : "rgba(0,229,255,0.2)"}`,
    borderRadius: 5, color: ok === true ? "#00e676" : ok === false ? "#e53935" : "#00e5ff",
    cursor: "pointer", fontFamily: "'Share Tech Mono', monospace",
  }),
  hint: { fontSize: 10, color: "rgba(0,229,255,0.3)", marginTop: 4 },
  saveBtn: {
    padding: "9px 24px", fontSize: 11, letterSpacing: 2,
    background: "rgba(0,229,255,0.12)",
    border: "1px solid rgba(0,229,255,0.35)",
    borderRadius: 6, color: "#00e5ff", cursor: "pointer",
    fontFamily: "'Share Tech Mono', monospace",
    transition: "background 0.15s",
  },
  statusBanner: (type) => ({
    padding: "8px 14px", borderRadius: 6, fontSize: 11, marginTop: 14,
    background: type === "success" ? "rgba(0,230,118,0.1)"
               : type === "error" ? "rgba(229,57,53,0.1)" : "rgba(0,229,255,0.06)",
    border: `1px solid ${type === "success" ? "rgba(0,230,118,0.3)"
             : type === "error" ? "rgba(229,57,53,0.3)" : "rgba(0,229,255,0.15)"}`,
    color: type === "success" ? "#00e676" : type === "error" ? "#e53935" : "#00e5ff",
  }),
  divider: { border: "none", borderTop: "1px solid rgba(0,229,255,0.08)", margin: "20px 0" },
  pqNote: {
    padding: "10px 14px", borderRadius: 6, fontSize: 10,
    background: "rgba(124,81,161,0.1)", border: "1px solid rgba(124,81,161,0.25)",
    color: "rgba(124,81,161,0.9)", lineHeight: 1.6, letterSpacing: 0.3,
  },
};

// ── Secure input field ────────────────────────────────────────────────────────
function SecretInput({ value, onChange, placeholder = "", ...rest }) {
  const [show, setShow] = useState(false);
  return (
    <div style={S.inputWrap}>
      <input
        {...rest}
        type={show ? "text" : "password"}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        style={{ ...S.input, fontFamily: show ? "monospace" : "monospace", letterSpacing: show ? 0 : 2 }}
      />
      <button type="button" style={S.revealBtn} onClick={() => setShow(s => !s)}>
        {show ? "🙈" : "👁"}
      </button>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function SettingsPage({ onClose }) {
  const [tab, setTab]         = useState("api_keys");
  const [settings, setSettings] = useState({});
  const [dirty, setDirty]     = useState({});
  const [status, setStatus]   = useState(null); // { type, msg }
  const [testing, setTesting] = useState({});   // { service: true/false/null }
  const [saving, setSaving]   = useState(false);

  // Load current settings on mount
  useEffect(() => {
    fetch(SETTINGS_URL)
      .then(r => r.json())
      .then(d => setSettings(d.settings || {}))
      .catch(() => setStatus({ type: "error", msg: "Failed to load settings" }));
  }, []);

  const set = (key, val) => {
    setDirty(d => ({ ...d, [key]: val }));
  };

  const get = (key) => {
    if (key in dirty) return dirty[key];
    const v = settings[key] || "";
    // Redacted values show as empty in the form so user must re-enter
    return v.startsWith("••••••••") ? "" : v;
  };

  const isConfigured = (key) => {
    if (key in dirty) return dirty[key].length > 0;
    const v = settings[key] || "";
    return v.length > 0;
  };

  const save = async () => {
    if (!Object.keys(dirty).length) return;
    setSaving(true);
    setStatus(null);
    try {
      const r = await fetch(SETTINGS_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(dirty),
      });
      const d = await r.json();
      if (r.ok && !d.errors?.length) {
        setStatus({ type: "success", msg: `Saved: ${d.updated.join(", ")}` });
        setDirty({});
        // Refresh settings
        const r2 = await fetch(SETTINGS_URL);
        const d2 = await r2.json();
        setSettings(d2.settings || {});
      } else {
        setStatus({ type: "error", msg: d.errors?.join("; ") || "Save failed" });
      }
    } catch (e) {
      setStatus({ type: "error", msg: "Network error saving settings" });
    } finally {
      setSaving(false);
    }
  };

  const testService = async (service) => {
    setTesting(t => ({ ...t, [service]: null }));
    try {
      const r = await fetch(`${TEST_URL}/${service}`, { method: "POST" });
      const d = await r.json();
      setTesting(t => ({ ...t, [service]: d.ok }));
      setStatus({ type: d.ok ? "success" : "error",
                  msg: d.ok ? `${service.toUpperCase()} connection OK${d.username ? ` (${d.username})` : ""}${d.version ? ` v${d.version}` : ""}` : `${service.toUpperCase()}: ${d.error}` });
    } catch {
      setTesting(t => ({ ...t, [service]: false }));
      setStatus({ type: "error", msg: `${service.toUpperCase()}: connection failed` });
    }
  };

  const hasDirty = Object.keys(dirty).length > 0;

  return (
    <div style={S.overlay} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={S.panel}>
        {/* Header */}
        <div style={S.header}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 18 }}>⚙</span>
            <span style={S.title}>// PLATFORM SETTINGS</span>
          </div>
          <button style={S.closeBtn} onClick={onClose}>✕</button>
        </div>

        {/* Tabs */}
        <div style={S.tabs}>
          {[
            ["api_keys",    "API KEYS"],
            ["credentials", "CREDENTIAL MONITOR"],
            ["dns",         "DNS / TRACER"],
            ["network",     "NETWORK"],
            ["security",    "SECURITY"],
          ].map(([k, label]) => (
            <button key={k} style={S.tab(tab === k)} onClick={() => setTab(k)}>{label}</button>
          ))}
        </div>

        {/* Body */}
        <div style={S.body}>
          {tab === "api_keys" && <TabApiKeys get={get} set={set} isConfigured={isConfigured} test={testService} testing={testing} />}
          {tab === "credentials" && <TabCredentials get={get} set={set} isConfigured={isConfigured} />}
          {tab === "dns" && <TabDns get={get} set={set} isConfigured={isConfigured} />}
          {tab === "network" && <TabNetwork get={get} set={set} />}
          {tab === "security" && <TabSecurity get={get} set={set} />}

          {/* Status banner */}
          {status && (
            <div style={S.statusBanner(status.type)}>{status.msg}</div>
          )}

          {/* Save / close row */}
          <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
            <button style={{ ...S.saveBtn, opacity: hasDirty ? 1 : 0.4 }} onClick={save} disabled={!hasDirty || saving}>
              {saving ? "SAVING…" : "SAVE CHANGES"}
            </button>
            {hasDirty && (
              <button style={{ ...S.saveBtn, color: "#e53935", borderColor: "rgba(229,57,53,0.35)" }}
                onClick={() => { setDirty({}); setStatus(null); }}>
                DISCARD
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Tab: API Keys ─────────────────────────────────────────────────────────────
function TabApiKeys({ get, set, isConfigured, test, testing }) {
  return (
    <div>
      <div style={S.pqNote}>
        All API keys are encrypted at rest (AES-256 via Fernet, PBKDF2-SHA256 KDF, 480k iterations).
        Keys are transmitted only over the internal Docker network.
        Post-quantum upgrade path: Kyber-1024 KEM + AES-256-GCM when liboqs-python stabilises.
      </div>

      <hr style={S.divider} />

      <div style={S.section}>
        <div style={S.sectionTitle}>// THREAT INTELLIGENCE FEEDS</div>

        <div style={S.row}>
          <label style={S.label}>OTX AlienVault API Key {isConfigured("otx_api_key") && "✓"}</label>
          <div style={{ display: "flex", gap: 8 }}>
            <SecretInput value={get("otx_api_key")} onChange={e => set("otx_api_key", e.target.value)}
              placeholder="Your OTX API key from otx.alienvault.com" style={{ flex: 1 }} />
            <button style={S.testBtn(testing.otx)} onClick={() => test("otx")}>TEST</button>
          </div>
          <div style={S.hint}>Free account at otx.alienvault.com — provides 19M+ daily threat indicators</div>
        </div>

        <div style={S.row}>
          <label style={S.label}>MISP Instance URL {isConfigured("misp_url") && "✓"}</label>
          <input type="url" value={get("misp_url")} onChange={e => set("misp_url", e.target.value)}
            placeholder="https://your-misp-instance.org"
            style={{ ...S.input, width: "100%", boxSizing: "border-box" }} />
        </div>

        <div style={S.row}>
          <label style={S.label}>MISP API Key {isConfigured("misp_api_key") && "✓"}</label>
          <div style={{ display: "flex", gap: 8 }}>
            <SecretInput value={get("misp_api_key")} onChange={e => set("misp_api_key", e.target.value)}
              placeholder="MISP automation key" style={{ flex: 1 }} />
            <button style={S.testBtn(testing.misp)} onClick={() => test("misp")}>TEST</button>
          </div>
        </div>

        <div style={S.row}>
          <label style={S.label}>Emerging Threats Pro API Key {isConfigured("et_pro_api_key") && "✓"}</label>
          <SecretInput value={get("et_pro_api_key")} onChange={e => set("et_pro_api_key", e.target.value)}
            placeholder="ET Pro key (leave blank for ET Open rules)" />
          <div style={S.hint}>ET Pro provides 6,000+ additional signatures over the free ET Open ruleset</div>
        </div>
      </div>

      <hr style={S.divider} />

      <div style={S.section}>
        <div style={S.sectionTitle}>// CREDENTIAL MONITORING</div>

        <div style={S.row}>
          <label style={S.label}>HaveIBeenPwned API Key {isConfigured("hibp_api_key") && "✓"}</label>
          <div style={{ display: "flex", gap: 8 }}>
            <SecretInput value={get("hibp_api_key")} onChange={e => set("hibp_api_key", e.target.value)}
              placeholder="HIBP API key from haveibeenpwned.com" style={{ flex: 1 }} />
            <button style={S.testBtn(testing.hibp)} onClick={() => test("hibp")}>TEST</button>
          </div>
          <div style={S.hint}>Required for email breach monitoring. Password checks use k-anonymity (no password is sent).</div>
        </div>
      </div>
    </div>
  );
}

// ── Tab: Credential Monitor ───────────────────────────────────────────────────
function TabCredentials({ get, set, isConfigured }) {
  const [credStatus, setCredStatus] = useState(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    fetch("/api/credentials/status")
      .then(r => r.json())
      .then(setCredStatus)
      .catch(() => {});
  }, []);

  const triggerRefresh = async () => {
    setChecking(true);
    await fetch("/api/credentials/refresh", { method: "POST" }).catch(() => {});
    setTimeout(() => setChecking(false), 3000);
  };

  return (
    <div>
      <div style={S.section}>
        <div style={S.sectionTitle}>// MONITORED EMAIL ADDRESSES</div>
        <div style={S.row}>
          <label style={S.label}>Email addresses to monitor (comma-separated)</label>
          <textarea
            value={get("monitored_emails")}
            onChange={e => set("monitored_emails", e.target.value)}
            placeholder="user@domain.com, admin@company.org"
            rows={3}
            style={{
              ...S.input, width: "100%", boxSizing: "border-box",
              resize: "vertical", fontFamily: "monospace", lineHeight: 1.6,
            }}
          />
          <div style={S.hint}>
            Checked against HaveIBeenPwned breach & paste databases every hour.
            Password exposure alerts published to Kafka `credential.alerts` topic.
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 8 }}>
          <label style={S.label}>Check interval (seconds):</label>
          <input type="number" min={300} max={86400}
            value={get("cred_check_interval") || "3600"}
            onChange={e => set("cred_check_interval", e.target.value)}
            style={{ ...S.input, width: 100 }} />
          <button style={S.testBtn(null)} onClick={triggerRefresh} disabled={checking}>
            {checking ? "CHECKING…" : "CHECK NOW"}
          </button>
        </div>
      </div>

      <hr style={S.divider} />

      {credStatus && (
        <div style={S.section}>
          <div style={S.sectionTitle}>// BREACH STATUS</div>
          {credStatus.monitored?.length === 0 ? (
            <div style={{ color: "rgba(0,229,255,0.4)", fontSize: 12 }}>No emails configured.</div>
          ) : (
            Object.entries(credStatus.status || {}).map(([email, info]) => (
              <div key={email} style={{
                padding: "10px 14px", marginBottom: 8, borderRadius: 6,
                background: info.breach_count > 0 ? "rgba(229,57,53,0.08)" : "rgba(0,230,118,0.06)",
                border: `1px solid ${info.breach_count > 0 ? "rgba(229,57,53,0.25)" : "rgba(0,230,118,0.2)"}`,
              }}>
                <div style={{ color: "#e8e8e8", fontSize: 12, marginBottom: 4 }}>{email}</div>
                <div style={{ display: "flex", gap: 16, fontSize: 11 }}>
                  <span style={{ color: info.breach_count > 0 ? "#e53935" : "#00e676" }}>
                    {info.breach_count} breach{info.breach_count !== 1 ? "es" : ""}
                  </span>
                  <span style={{ color: info.paste_count > 0 ? "#FF6F00" : "rgba(0,229,255,0.35)" }}>
                    {info.paste_count} paste{info.paste_count !== 1 ? "s" : ""}
                  </span>
                  {info.password_exposed && (
                    <span style={{ color: "#7b0000", fontWeight: 700 }}>⚠ PASSWORD EXPOSED</span>
                  )}
                  {info.most_recent_breach && (
                    <span style={{ color: "rgba(0,229,255,0.4)" }}>Last: {info.most_recent_breach}</span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      <div style={S.section}>
        <div style={S.sectionTitle}>// PASSWORD BREACH CHECK</div>
        <PasswordChecker />
      </div>
    </div>
  );
}

function PasswordChecker() {
  const [pw, setPw] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const check = async () => {
    if (!pw) return;
    setLoading(true); setResult(null);
    try {
      const r = await fetch("/api/credentials/check-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw }),
      });
      setResult(await r.json());
    } catch {
      setResult({ error: "Check failed" });
    } finally { setLoading(false); setPw(""); }
  };

  return (
    <div>
      <div style={{ color: "rgba(0,229,255,0.4)", fontSize: 10, marginBottom: 10 }}>
        Uses k-anonymity — only the first 5 chars of SHA1(password) are sent to HIBP. The password itself never leaves this browser.
      </div>
      <div style={{ display: "flex", gap: 8 }}>
        <input type="password" value={pw} onChange={e => setPw(e.target.value)}
          placeholder="Enter password to check" style={{ ...S.input, flex: 1 }}
          onKeyDown={e => e.key === "Enter" && check()} autoComplete="new-password" />
        <button style={S.testBtn(null)} onClick={check} disabled={loading || !pw}>
          {loading ? "…" : "CHECK"}
        </button>
      </div>
      {result && !result.error && (
        <div style={S.statusBanner(result.pwned ? "error" : "success")}>
          {result.pwned
            ? `⚠ Password seen ${result.count.toLocaleString()}× in breaches — DO NOT USE`
            : "✓ Password not found in known breaches"}
        </div>
      )}
    </div>
  );
}

// ── Tab: DNS / Tracer ─────────────────────────────────────────────────────────
function TabDns({ get, set, isConfigured }) {
  const [traceIp, setTraceIp] = useState("");
  const [traceResult, setTraceResult] = useState(null);

  const triggerTrace = async () => {
    if (!traceIp) return;
    try {
      const r = await fetch("/api/dns/trace", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: traceIp }),
      });
      const d = await r.json();
      setTraceResult(d);
    } catch (e) {
      setTraceResult({ error: String(e) });
    }
  };

  return (
    <div>
      <div style={S.section}>
        <div style={S.sectionTitle}>// DGA DETECTION THRESHOLDS</div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div style={S.row}>
            <label style={S.label}>Shannon Entropy Threshold (default: 3.6)</label>
            <input type="number" step={0.1} min={2.0} max={5.0}
              value={get("dga_entropy_thresh") || "3.6"}
              onChange={e => set("dga_entropy_thresh", e.target.value)}
              style={S.input} />
            <div style={S.hint}>Higher = fewer false positives but may miss low-entropy DGA</div>
          </div>

          <div style={S.row}>
            <label style={S.label}>NXDomain Burst Limit (default: 10)</label>
            <input type="number" min={3} max={100}
              value={get("nxdomain_burst_limit") || "10"}
              onChange={e => set("nxdomain_burst_limit", e.target.value)}
              style={S.input} />
            <div style={S.hint}>Alerts if a source IP generates this many NXDomains in 60s</div>
          </div>
        </div>

        <div style={S.row}>
          <label style={S.label}>RPZ Blocked Domains (comma-separated)</label>
          <textarea
            value={get("rpz_blocked_domains")}
            onChange={e => set("rpz_blocked_domains", e.target.value)}
            placeholder="malware.com, c2server.net, phishing.org"
            rows={3}
            style={{ ...S.input, width: "100%", boxSizing: "border-box", resize: "vertical" }}
          />
          <div style={S.hint}>Domains in this list trigger an immediate alert when queried</div>
        </div>
      </div>

      <hr style={S.divider} />

      <div style={S.section}>
        <div style={S.sectionTitle}>// EPHEMERAL PATH TRACER</div>
        <div style={S.pqNote}>
          The ephemeral tracer sends ICMP probes with randomised source IP (RFC1918) and MAC headers
          to reveal the true network path to a suspicious IP without exposing the sensor identity.
          Each probe is one-time use — no session state is maintained. Requires ENABLE_EPHEMERAL_TRACER=true
          in docker-compose and CAP_NET_RAW capability. Only use on authorised networks.
        </div>

        <div style={{ marginTop: 14, display: "flex", gap: 8 }}>
          <input type="text" value={traceIp} onChange={e => setTraceIp(e.target.value)}
            placeholder="Target IP to trace" style={{ ...S.input, flex: 1 }} />
          <button style={S.testBtn(null)} onClick={triggerTrace}>TRACE</button>
        </div>
        {traceResult && (
          <pre style={{
            marginTop: 10, padding: 12, background: "rgba(0,229,255,0.03)",
            border: "1px solid rgba(0,229,255,0.1)", borderRadius: 6,
            fontSize: 11, color: "#e8e8e8", overflow: "auto",
          }}>
            {JSON.stringify(traceResult, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

// ── Tab: Network ──────────────────────────────────────────────────────────────
function TabNetwork({ get, set }) {
  return (
    <div>
      <div style={S.section}>
        <div style={S.sectionTitle}>// SENSOR LOCATION</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div style={S.row}>
            <label style={S.label}>Home Latitude</label>
            <input type="number" step={0.01} min={-90} max={90}
              value={get("home_lat") || "38.9"}
              onChange={e => set("home_lat", e.target.value)}
              style={S.input} />
          </div>
          <div style={S.row}>
            <label style={S.label}>Home Longitude</label>
            <input type="number" step={0.01} min={-180} max={180}
              value={get("home_lon") || "-77.0"}
              onChange={e => set("home_lon", e.target.value)}
              style={S.input} />
          </div>
        </div>

        <div style={S.row}>
          <label style={S.label}>Network Range (for asset discovery)</label>
          <input type="text"
            value={get("network_range") || "192.168.1.0/24"}
            onChange={e => set("network_range", e.target.value)}
            placeholder="192.168.1.0/24"
            style={S.input} />
        </div>

        <div style={S.row}>
          <label style={S.label}>Trusted IPs (never auto-blocked, comma-separated)</label>
          <textarea
            value={get("trusted_ips")}
            onChange={e => set("trusted_ips", e.target.value)}
            placeholder="192.168.1.1, 10.0.0.0/8"
            rows={2}
            style={{ ...S.input, width: "100%", boxSizing: "border-box", resize: "vertical" }}
          />
        </div>
      </div>

      <hr style={S.divider} />

      <div style={S.section}>
        <div style={S.sectionTitle}>// SOAR AUTO-BLOCK SETTINGS</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
          <div style={S.row}>
            <label style={S.label}>Severity Threshold (1=critical)</label>
            <input type="number" min={1} max={4}
              value={get("severity_threshold") || "2"}
              onChange={e => set("severity_threshold", e.target.value)}
              style={S.input} />
          </div>
          <div style={S.row}>
            <label style={S.label}>Min Alerts Before Block</label>
            <input type="number" min={1} max={50}
              value={get("min_alerts_to_block") || "3"}
              onChange={e => set("min_alerts_to_block", e.target.value)}
              style={S.input} />
          </div>
          <div style={S.row}>
            <label style={S.label}>Block TTL (seconds, 0=permanent)</label>
            <input type="number" min={0}
              value={get("block_ttl_seconds") || "3600"}
              onChange={e => set("block_ttl_seconds", e.target.value)}
              style={S.input} />
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Tab: Security ─────────────────────────────────────────────────────────────
function TabSecurity({ get, set }) {
  return (
    <div>
      <div style={S.pqNote}>
        Post-quantum security roadmap for this platform:
        {"\n"}• Storage: AES-256-GCM keys (128-bit PQ security via Grover bound) — DONE
        {"\n"}• Transport: TLS 1.3 with X25519 ECDHE (upgrade to X25519Kyber768 when Go/Java support lands in Kafka)
        {"\n"}• Kafka: SASL_SSL + TLS 1.3 — configure via KAFKA_SSL_* env vars
        {"\n"}• Neo4j: bolt+s (TLS) — set NEO4J_dbms_ssl_policy_bolt_enabled=true
        {"\n"}• Future: CRYSTALS-Kyber KEM + CRYSTALS-Dilithium signatures via liboqs
      </div>

      <hr style={S.divider} />

      <div style={S.section}>
        <div style={S.sectionTitle}>// INTERNAL API TOKEN</div>
        <div style={S.row}>
          <label style={S.label}>Internal API Token (for service-to-service auth)</label>
          <SecretInput value={get("internal_api_token")}
            onChange={e => set("internal_api_token", e.target.value)}
            placeholder="Generate with: openssl rand -hex 32" />
          <div style={S.hint}>Used by threat_intel and credential_monitor to fetch API keys from settings_api</div>
        </div>
      </div>

      <hr style={S.divider} />

      <div style={S.section}>
        <div style={S.sectionTitle}>// BLOCKED COUNTRIES (GEO-BLOCKING)</div>
        <div style={S.row}>
          <label style={S.label}>ISO country codes to auto-block (comma-separated)</label>
          <input type="text"
            value={get("blocked_countries")}
            onChange={e => set("blocked_countries", e.target.value)}
            placeholder="KP, IR, RU (leave blank to disable)"
            style={S.input} />
          <div style={S.hint}>Requires GeoIP enrichment. Matching src IPs are passed to SOAR blocker.</div>
        </div>
      </div>

      <hr style={S.divider} />

      <div style={S.section}>
        <div style={S.sectionTitle}>// AI LLM MODELS</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div style={S.row}>
            <label style={S.label}>Primary Model</label>
            <input type="text"
              value={get("ollama_model") || "aratan/Ministral-3-14B-Reasoning-2512:latest"}
              onChange={e => set("ollama_model", e.target.value)}
              style={S.input} />
          </div>
          <div style={S.row}>
            <label style={S.label}>Secondary / Security Model</label>
            <input type="text"
              value={get("secondary_model") || "cybersecserver/matrix-ai:latest"}
              onChange={e => set("secondary_model", e.target.value)}
              style={S.input} />
          </div>
        </div>
      </div>
    </div>
  );
}
