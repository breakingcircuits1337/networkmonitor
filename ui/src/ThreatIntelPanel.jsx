import React, { useState, useEffect, useRef, useCallback } from "react";

const INTEL_CHAT_URL = "/api/intel-chat";
const IOC_FEED_URL   = "/api/ioc/feed";
const RULES_URL      = "/api/ioc/rules";
const REFRESH_URL    = "/api/ioc/refresh";
const CRED_URL       = "/api/credentials/status";

const IOC_TYPE_COLOR = {
  ip:     "#e53935",
  domain: "#FF6F00",
  hash:   "#7c51a1",
  cve:    "#00BCD4",
  url:    "#FFC107",
};

const SOURCE_COLOR = {
  OTX:       "#00e5ff",
  "CISA-KEV": "#e53935",
  MISP:      "#7c51a1",
};

function IOCBadge({ type }) {
  return (
    <span style={{
      display: "inline-block",
      padding: "1px 6px", borderRadius: 3, fontSize: 9,
      fontWeight: 700, letterSpacing: 1,
      background: `${IOC_TYPE_COLOR[type] || "#546E7A"}22`,
      color: IOC_TYPE_COLOR[type] || "#546E7A",
      border: `1px solid ${IOC_TYPE_COLOR[type] || "#546E7A"}44`,
    }}>
      {type?.toUpperCase()}
    </span>
  );
}

function SourceBadge({ source }) {
  const col = SOURCE_COLOR[source] || "rgba(0,229,255,0.5)";
  return (
    <span style={{
      display: "inline-block",
      padding: "1px 6px", borderRadius: 3, fontSize: 9,
      color: col, border: `1px solid ${col}44`,
      background: `${col}10`,
    }}>
      {source}
    </span>
  );
}

function IOCCard({ ioc }) {
  const [expanded, setExpanded] = useState(false);
  const conf = ioc.confidence != null ? Math.round(ioc.confidence * 100) : null;

  return (
    <div
      onClick={() => setExpanded(e => !e)}
      style={{
        padding: "8px 10px", marginBottom: 5,
        background: "rgba(0,229,255,0.03)",
        border: `1px solid ${IOC_TYPE_COLOR[ioc.ioc_type] || "rgba(0,229,255,0.1)"}22`,
        borderRadius: 5, cursor: "pointer",
        transition: "background 0.1s",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
        <IOCBadge type={ioc.ioc_type} />
        <SourceBadge source={ioc.source} />
        <span style={{
          fontFamily: "monospace", fontSize: 11, color: "#e8e8e8",
          flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        }}>
          {ioc.indicator}
        </span>
        {conf != null && (
          <span style={{
            fontSize: 10,
            color: conf >= 80 ? "#e53935" : conf >= 60 ? "#FF6F00" : "rgba(0,229,255,0.4)",
          }}>
            {conf}%
          </span>
        )}
      </div>

      {expanded && (
        <div style={{ marginTop: 8, fontSize: 10, color: "rgba(0,229,255,0.6)", lineHeight: 1.7 }}>
          <div><b>Threat:</b> {ioc.threat_type || "—"}</div>
          {ioc.pulse_name && <div><b>Pulse:</b> {ioc.pulse_name}</div>}
          {ioc.description && <div><b>Info:</b> {ioc.description.slice(0, 200)}</div>}
          {ioc.comment && <div><b>Comment:</b> {ioc.comment}</div>}
          <div><b>Seen:</b> {ioc.timestamp ? new Date(ioc.timestamp).toLocaleString() : "—"}</div>
          {ioc.suricata_rule && (
            <div style={{ marginTop: 6 }}>
              <div style={{ color: "#00e5ff", marginBottom: 2 }}>Suricata Rule:</div>
              <pre style={{
                fontSize: 9, padding: "6px 8px", borderRadius: 4,
                background: "rgba(0,229,255,0.05)",
                border: "1px solid rgba(0,229,255,0.1)",
                overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all",
                color: "#00e676",
              }}>
                {ioc.suricata_rule}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AnalystChat({ onNewRule }) {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content: "Threat Intel Analyst ready. Ask me about the current IOC feed, threat patterns, or request Suricata rules for specific indicators.",
    }
  ]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = async (text = input) => {
    if (!text.trim() || streaming) return;
    setMessages(prev => [...prev, { role: "user", content: text }]);
    setInput("");
    const msgId = Date.now();
    setMessages(prev => [...prev, { role: "assistant", content: "", _id: msgId, streaming: true }]);
    setStreaming(true);

    try {
      const res = await fetch(INTEL_CHAT_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text }),
      });
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "", full = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith("data:")) continue;
          try {
            const chunk = JSON.parse(line.slice(5).trim());
            if (chunk.token) {
              full += chunk.token;
              setMessages(prev => prev.map(m => m._id === msgId ? { ...m, content: full } : m));
            }
            if (chunk.done) {
              setMessages(prev => prev.map(m =>
                m._id === msgId ? { ...m, content: full, streaming: false } : m
              ));
              // Extract Suricata rules from the response and surface them
              const ruleMatch = full.match(/alert\s+(ip|dns|tcp|udp|http)[^)]+\)/g);
              if (ruleMatch && onNewRule) ruleMatch.forEach(r => onNewRule(r));
            }
          } catch {}
        }
      }
    } catch {
      setMessages(prev => prev.map(m =>
        m._id === msgId ? { ...m, content: "⚠ Intel chat unavailable — is threat_intel service running?", streaming: false } : m
      ));
    } finally {
      setStreaming(false);
    }
  };

  const quickPrompts = [
    "Summarize the current threat feed",
    "What IPs should I block immediately?",
    "Generate rules for all C2 domains",
    "Are any CISA KEV CVEs affecting common services?",
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Messages */}
      <div style={{
        flex: 1, overflowY: "auto", padding: "8px",
        display: "flex", flexDirection: "column", gap: 6,
      }}>
        {messages.map((m, i) => (
          <div key={i} style={{
            alignSelf: m.role === "user" ? "flex-end" : "flex-start",
            maxWidth: "90%",
            background: m.role === "user" ? "rgba(0,110,200,0.4)" : "rgba(0,229,255,0.05)",
            border: `1px solid ${m.role === "user" ? "rgba(0,110,200,0.3)" : "rgba(0,229,255,0.1)"}`,
            borderRadius: m.role === "user" ? "14px 14px 4px 14px" : "14px 14px 14px 4px",
            padding: "7px 11px", fontSize: 11,
            color: m.role === "user" ? "#e8e8e8" : "#c8d8e8",
            lineHeight: 1.55, whiteSpace: "pre-wrap",
          }}>
            {m.content}
            {m.streaming && <span style={{ opacity: 0.5 }}>▍</span>}
          </div>
        ))}
        <div ref={endRef} />
      </div>

      {/* Quick prompts */}
      <div style={{ display: "flex", gap: 4, flexWrap: "wrap", padding: "4px 8px" }}>
        {quickPrompts.map((p, i) => (
          <button key={i} onClick={() => send(p)} style={{
            padding: "3px 8px", fontSize: 9, letterSpacing: 0.5,
            border: "1px solid rgba(0,229,255,0.15)",
            borderRadius: 10, background: "rgba(0,229,255,0.04)",
            color: "rgba(0,229,255,0.6)", cursor: "pointer",
          }}>
            {p}
          </button>
        ))}
      </div>

      {/* Input */}
      <div style={{ display: "flex", gap: 6, padding: "6px 8px" }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()}
          placeholder="Ask the threat analyst…"
          style={{
            flex: 1, padding: "7px 10px",
            background: "rgba(0,229,255,0.04)",
            border: "1px solid rgba(0,229,255,0.18)",
            borderRadius: 6, color: "#e8e8e8", fontSize: 11,
            fontFamily: "monospace", outline: "none",
          }}
        />
        <button onClick={() => send()} disabled={streaming || !input.trim()} style={{
          padding: "7px 12px",
          background: "rgba(0,229,255,0.1)",
          border: "1px solid rgba(0,229,255,0.2)",
          borderRadius: 6, color: "#00e5ff",
          cursor: streaming ? "wait" : "pointer", fontSize: 13,
        }}>
          {streaming ? "…" : "➤"}
        </button>
      </div>
    </div>
  );
}

export default function ThreatIntelPanel({ onClose }) {
  const [iocs, setIocs]       = useState([]);
  const [total, setTotal]     = useState(0);
  const [rules, setRules]     = useState([]);
  const [credStatus, setCredStatus] = useState(null);
  const [activeTab, setActiveTab]   = useState("feed");
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter]   = useState("");

  const load = useCallback(async () => {
    try {
      const [fi, ri, ci] = await Promise.allSettled([
        fetch(IOC_FEED_URL).then(r => r.json()),
        fetch(RULES_URL).then(r => r.json()),
        fetch(CRED_URL).then(r => r.json()),
      ]);
      if (fi.status === "fulfilled") { setIocs(fi.value.iocs || []); setTotal(fi.value.total || 0); }
      if (ri.status === "fulfilled") { setRules(ri.value.rules || []); }
      if (ci.status === "fulfilled") { setCredStatus(ci.value); }
    } catch {}
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, [load]);

  const refresh = async () => {
    setRefreshing(true);
    await fetch(REFRESH_URL, { method: "POST" }).catch(() => {});
    setTimeout(() => { load(); setRefreshing(false); }, 3000);
  };

  const addRule = (rule) => setRules(prev => [rule, ...prev.slice(0, 99)]);

  const filtered = iocs.filter(ioc =>
    !filter || ioc.indicator?.includes(filter) ||
    ioc.ioc_type?.includes(filter) || ioc.source?.includes(filter) ||
    ioc.threat_type?.includes(filter)
  );

  const totalBreaches = credStatus
    ? Object.values(credStatus.status || {}).reduce((s, e) => s + e.breach_count, 0) : 0;

  // Panel layout — fixed right side panel
  return (
    <div style={{
      position: "fixed", top: 46, right: 0, bottom: 0, zIndex: 1400,
      width: 440,
      display: "flex", flexDirection: "column",
      background: "rgba(0,4,12,0.97)",
      borderLeft: "1px solid rgba(0,229,255,0.18)",
      boxShadow: "-12px 0 40px rgba(0,0,0,0.6)",
      fontFamily: "'Share Tech Mono', monospace",
    }}>
      {/* Header */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "10px 14px",
        borderBottom: "1px solid rgba(0,229,255,0.12)",
        background: "rgba(0,229,255,0.04)",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ color: "#00e5ff", fontSize: 13, letterSpacing: 2 }}>// THREAT INTEL</span>
          <span style={{
            fontSize: 10, padding: "1px 6px", borderRadius: 3,
            background: "rgba(229,57,53,0.15)", color: "#e53935",
            border: "1px solid rgba(229,57,53,0.25)",
          }}>
            {total} IOCs
          </span>
          {totalBreaches > 0 && (
            <span style={{
              fontSize: 10, padding: "1px 6px", borderRadius: 3,
              background: "rgba(229,57,53,0.2)", color: "#e53935",
              border: "1px solid rgba(229,57,53,0.35)", fontWeight: 700,
            }}>
              {totalBreaches} BREACH{totalBreaches !== 1 ? "ES" : ""}
            </span>
          )}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={refresh} disabled={refreshing} style={{
            background: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.2)",
            borderRadius: 4, color: "#00e5ff", cursor: "pointer", fontSize: 11, padding: "3px 8px",
          }}>
            {refreshing ? "↻…" : "↻ REFRESH"}
          </button>
          <button onClick={onClose} style={{
            background: "none", border: "none", color: "#00e5ff", fontSize: 16, cursor: "pointer",
          }}>✕</button>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid rgba(0,229,255,0.1)", flexShrink: 0 }}>
        {[
          ["feed", `FEED (${filtered.length})`],
          ["analyst", "ANALYST CHAT"],
          ["rules", `RULES (${rules.length})`],
          ["creds", `CREDS${totalBreaches > 0 ? ` ⚠${totalBreaches}` : ""}`],
        ].map(([k, label]) => (
          <button key={k} onClick={() => setActiveTab(k)} style={{
            flex: 1, padding: "8px 4px", fontSize: 9, letterSpacing: 1,
            border: "none", fontFamily: "'Share Tech Mono', monospace",
            background: activeTab === k ? "rgba(0,229,255,0.08)" : "transparent",
            color: activeTab === k ? "#00e5ff" : "rgba(0,229,255,0.4)",
            borderBottom: activeTab === k ? "2px solid #00e5ff" : "2px solid transparent",
            cursor: "pointer",
          }}>
            {label}
          </button>
        ))}
      </div>

      {/* Feed tab */}
      {activeTab === "feed" && (
        <div style={{ display: "flex", flexDirection: "column", flex: 1, overflow: "hidden" }}>
          <div style={{ padding: "8px 10px", flexShrink: 0 }}>
            <input
              value={filter} onChange={e => setFilter(e.target.value)}
              placeholder="Filter by IP, domain, source, threat type…"
              style={{
                width: "100%", boxSizing: "border-box",
                padding: "6px 10px", fontSize: 11,
                background: "rgba(0,229,255,0.04)",
                border: "1px solid rgba(0,229,255,0.15)",
                borderRadius: 5, color: "#e8e8e8", fontFamily: "monospace", outline: "none",
              }}
            />
          </div>
          <div style={{ flex: 1, overflowY: "auto", padding: "0 10px 10px" }}>
            {filtered.length === 0 ? (
              <div style={{ color: "rgba(0,229,255,0.3)", fontSize: 11, textAlign: "center", marginTop: 40 }}>
                {total === 0
                  ? "No IOCs loaded yet.\nConfigure API keys in Settings and click REFRESH."
                  : "No IOCs match filter."}
              </div>
            ) : (
              filtered.slice().reverse().map((ioc, i) => <IOCCard key={i} ioc={ioc} />)
            )}
          </div>
        </div>
      )}

      {/* Analyst chat tab */}
      {activeTab === "analyst" && (
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <AnalystChat onNewRule={addRule} />
        </div>
      )}

      {/* Rules tab */}
      {activeTab === "rules" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "10px" }}>
          {rules.length === 0 ? (
            <div style={{ color: "rgba(0,229,255,0.3)", fontSize: 11, textAlign: "center", marginTop: 40 }}>
              No rules generated yet.
            </div>
          ) : (
            rules.map((rule, i) => (
              <pre key={i} style={{
                fontSize: 9, padding: "7px 10px", marginBottom: 5,
                background: "rgba(0,230,118,0.04)",
                border: "1px solid rgba(0,230,118,0.15)",
                borderRadius: 4, color: "#00e676",
                overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all",
              }}>
                {rule}
              </pre>
            ))
          )}
        </div>
      )}

      {/* Credentials tab */}
      {activeTab === "creds" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "10px" }}>
          {!credStatus ? (
            <div style={{ color: "rgba(0,229,255,0.3)", fontSize: 11, textAlign: "center", marginTop: 40 }}>
              Credential monitor unavailable.
            </div>
          ) : credStatus.monitored?.length === 0 ? (
            <div style={{ color: "rgba(0,229,255,0.3)", fontSize: 11, textAlign: "center", marginTop: 40 }}>
              No emails configured. Add addresses in Settings → Credential Monitor.
            </div>
          ) : (
            Object.entries(credStatus.status || {}).map(([email, info]) => (
              <div key={email} style={{
                padding: "10px 12px", marginBottom: 8,
                background: info.breach_count > 0 ? "rgba(229,57,53,0.08)" : "rgba(0,230,118,0.05)",
                border: `1px solid ${info.breach_count > 0 ? "rgba(229,57,53,0.3)" : "rgba(0,230,118,0.2)"}`,
                borderRadius: 6,
              }}>
                <div style={{ color: "#e8e8e8", fontSize: 11, marginBottom: 6 }}>{email}</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 10, fontSize: 10 }}>
                  <span style={{ color: info.breach_count > 0 ? "#e53935" : "#00e676" }}>
                    {info.breach_count === 0 ? "✓ No breaches" : `⚠ ${info.breach_count} breach${info.breach_count !== 1 ? "es" : ""}`}
                  </span>
                  <span style={{ color: info.paste_count > 0 ? "#FF6F00" : "rgba(0,229,255,0.3)" }}>
                    {info.paste_count} paste{info.paste_count !== 1 ? "s" : ""}
                  </span>
                  {info.password_exposed && (
                    <span style={{ color: "#7b0000", fontWeight: 700 }}>PASSWORD EXPOSED</span>
                  )}
                </div>
                {info.most_recent_breach && (
                  <div style={{ color: "rgba(0,229,255,0.4)", fontSize: 9, marginTop: 4 }}>
                    Most recent: {info.most_recent_breach}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
