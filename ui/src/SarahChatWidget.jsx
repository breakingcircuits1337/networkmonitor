import React, { useState, useEffect, useRef, useCallback } from "react";

// All URLs are relative — served through the nginx proxy.
// Works from any LAN machine hitting port 8080.
const CHAT_URL        = "/api/chat";
const CHAT_STREAM_URL = "/api/chat/stream";
const EVENTS_URL      = "/events";
const SUMMARY_URL     = "/api/summary";

const SEV_COLOUR = {
  critical: "#7b0000", high: "#e53935", medium: "#FF6F00",
  low: "#FFC107", info: "#42A5F5",
};

// TTS settings by alert severity
const TTS_PROFILE = {
  critical: { rate: 0.75, pitch: 1.3, volume: 1.0 },
  high:     { rate: 0.78, pitch: 1.2, volume: 1.0 },
  medium:   { rate: 0.82, pitch: 1.1, volume: 0.9 },
  default:  { rate: 0.80, pitch: 1.0, volume: 0.9 },
};

export default function SarahChatWidget({ darkMode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    { role: "assistant", content: "Hi! I'm Sarah. Ask me about your network, or enable alerts to hear security notifications." }
  ]);
  const [input,         setInput]         = useState("");
  const [isListening,   setIsListening]   = useState(false);
  const [isSpeaking,    setIsSpeaking]    = useState(false);
  const [alertsEnabled, setAlertsEnabled] = useState(true);
  const [connected,     setConnected]     = useState(false);
  const [summaryLoaded, setSummaryLoaded] = useState(false);

  const recognitionRef = useRef(null);
  const synthRef       = useRef(null);
  const messagesEndRef = useRef(null);
  const evtRef         = useRef(null);

  // Auto-scroll to latest message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Init speech synthesis + recognition
  useEffect(() => {
    synthRef.current = window.speechSynthesis;

    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (SR) {
      const rec = new SR();
      rec.continuous     = false;
      rec.interimResults = false;
      rec.lang           = "en-US";

      rec.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        setInput(transcript);
        setIsListening(false);
        handleSend(transcript);
      };
      rec.onend  = () => setIsListening(false);
      rec.onerror = () => setIsListening(false);
      recognitionRef.current = rec;
    }
  }, []); // eslint-disable-line

  // Fetch scheduled threat summary when widget first opens
  useEffect(() => {
    if (!isOpen || summaryLoaded) return;
    setSummaryLoaded(true);
    fetch(SUMMARY_URL, { signal: AbortSignal.timeout(8000) })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data) return;
        const narrative = data.narrative || data.summary;
        if (!narrative || narrative.startsWith("No analyses")) return;
        const type    = data.type || "scheduled";
        const period  = data.period_minutes ? ` (last ${data.period_minutes}min)` : "";
        const counts  = data.total_analyzed ? ` — ${data.total_analyzed} events analyzed` : "";
        const prefix  = type === "none" ? "" : `Threat summary${period}${counts}:\n\n`;
        setMessages(prev => [...prev, {
          role: "assistant",
          content: prefix + narrative,
          badge: type === "scheduled" ? "scheduled-summary" : null,
        }]);
      })
      .catch(() => {});
  }, [isOpen, summaryLoaded]);

  // SSE stream — listen for live alerts and VoIP events
  useEffect(() => {
    if (!alertsEnabled) {
      evtRef.current?.close();
      evtRef.current = null;
      setConnected(false);
      return;
    }

    const connect = () => {
      const src = new EventSource(EVENTS_URL);
      evtRef.current = src;
      src.onopen  = () => setConnected(true);
      src.onerror = () => {
        setConnected(false);
        src.close();
        setTimeout(connect, 5000);
      };
      src.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const topic = data.topic || "";

          // IDS / security alert
          if (
            topic === "security.alerts" || topic === "alert.correlated" ||
            data.event_type === "ids_alert" || data.alert_signature_id
          ) {
            const sig = data.alert?.signature || data.signature || data.alert_signature || "Security Event";
            const isPrivate = ip => !ip || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
            const extIp = !isPrivate(data.src_ip) ? data.src_ip : (!isPrivate(data.dst_ip) ? data.dst_ip : data.src_ip);
            const src = extIp || "Unknown";
            const sev = String(data.alert?.severity ?? data.severity ?? "").toLowerCase();
            const sevLabel = sev === "1" ? "CRITICAL" : sev === "2" ? "HIGH" : sev === "3" ? "MEDIUM" : "ALERT";
            const msg = `🚨 ${sevLabel}: ${sig} — ${src}`;
            setMessages(prev => [...prev, { role: "system", content: msg, severity: sev }]);
            if (alertsEnabled && (sev === "1" || sev === "critical" || sev === "2" || sev === "high")) speak(msg, sev);
          }

          // AI analysis result
          else if (topic === "ai.analysis") {
            const sev = data.severity || "unknown";
            if (sev === "critical" || sev === "high") {
              const msg = `🤖 AI [${sev.toUpperCase()}]: ${data.summary || "Threat detected"} — ${data.src_ip || "?"}`;
              setMessages(prev => [...prev, { role: "system", content: msg, severity: sev, isAi: true }]);
              if (alertsEnabled) speak(msg, sev);
            }
          }

          // VoIP event
          else if (topic === "voip.events" || data.event_type === "voip") {
            const method = data.method || "Call";
            const src = data.src_ip || "Unknown";
            const msg = `📞 VoIP ${method} from ${src}`;
            setMessages(prev => [...prev, { role: "system", content: msg, severity: "voip" }]);
            // Only speak VoIP if critical (e.g. INVITE flood) — don't spam
          }

          // Block action
          else if (topic === "blocklist.actions") {
            const msg = `🛡 Blocked ${data.ip} — ${data.llm_reason || "threshold exceeded"}`;
            setMessages(prev => [...prev, { role: "system", content: msg, severity: "high" }]);
            if (alertsEnabled) speak(msg, "high");
          }
        } catch {}
      };
    };

    connect();
    return () => { evtRef.current?.close(); setConnected(false); };
  }, [alertsEnabled]); // eslint-disable-line

  const speak = useCallback((text, severity) => {
    const synth = synthRef.current;
    if (!synth) return;
    synth.cancel();
    const profile = TTS_PROFILE[severity] || TTS_PROFILE.default;
    const utt = new SpeechSynthesisUtterance(text);
    utt.rate   = profile.rate;
    utt.pitch  = profile.pitch;
    utt.volume = profile.volume;
    utt.onstart = () => setIsSpeaking(true);
    utt.onend   = () => setIsSpeaking(false);
    utt.onerror = () => setIsSpeaking(false);
    synth.speak(utt);
  }, []);

  const stopSpeaking = () => synthRef.current?.cancel();

  const toggleListening = () => {
    const rec = recognitionRef.current;
    if (!rec) {
      setMessages(prev => [...prev, { role: "system", content: "Voice input not supported in this browser." }]);
      return;
    }
    if (isListening) {
      rec.stop();
      setIsListening(false);
    } else {
      try { rec.start(); setIsListening(true); }
      catch { setIsListening(false); }
    }
  };

  const handleSend = async (text = input) => {
    if (!text?.trim()) return;
    setMessages(prev => [...prev, { role: "user", content: text }]);
    setInput("");

    // Add an empty assistant bubble we'll stream tokens into
    const msgId = Date.now();
    setMessages(prev => [...prev, { role: "assistant", content: "", _id: msgId, streaming: true }]);

    try {
      const res = await fetch(CHAT_STREAM_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text }),
      });
      if (!res.ok) throw new Error("API error");

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let   buffer  = "";
      let   fullText = "";
      let   modelUsed = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();           // keep incomplete line
        for (const line of lines) {
          if (!line.startsWith("data:")) continue;
          try {
            const chunk = JSON.parse(line.slice(5).trim());
            if (chunk.model) modelUsed = chunk.model;
            if (chunk.token) {
              fullText += chunk.token;
              setMessages(prev => prev.map(m =>
                m._id === msgId ? { ...m, content: fullText } : m
              ));
            }
            if (chunk.done) {
              setMessages(prev => prev.map(m =>
                m._id === msgId
                  ? { ...m, content: fullText, streaming: false, model: modelUsed, source: "ollama" }
                  : m
              ));
              speak(fullText, "default");
            }
          } catch {}
        }
      }
    } catch {
      setMessages(prev => prev.map(m =>
        m._id === msgId
          ? { ...m, content: "⚠️ Can't reach Sarah API. Check the connection.", streaming: false }
          : m
      ));
    }
  };

  const quickActions = [
    { label: "📊 Status",      cmd: "What is the current network status?" },
    { label: "🚨 Alerts",      cmd: "Show recent security alerts" },
    { label: "📋 Summary",     cmd: "Give me a threat summary" },
    { label: "📞 VoIP",        cmd: "Show recent VoIP calls" },
  ];

  // Colours
  const bg    = darkMode ? "#1a1b1e" : "#fff";
  const msgBg = { user: "#2d78d8", assistant: darkMode ? "#252629" : "#f0f0f0", system: "#2a2020" };
  const msgText = { user: "#fff", assistant: darkMode ? "#e8e8e8" : "#222", system: "#ffaaaa" };

  return (
    <>
      {/* FAB button */}
      <button
        onClick={() => setIsOpen(o => !o)}
        title="Sarah AI Chat"
        style={{
          position: "fixed", bottom: 22, right: 22,
          width: 62, height: 62, borderRadius: "50%",
          background: isSpeaking ? "#e53935" : connected ? "#27ae60" : "#555",
          color: "#fff", border: "none", fontSize: 26, cursor: "pointer",
          boxShadow: "0 4px 18px rgba(0,0,0,0.45)", zIndex: 10000,
          display: "flex", alignItems: "center", justifyContent: "center",
          animation: isSpeaking ? "pulse 0.9s infinite" : "none",
          transition: "background 0.3s",
        }}
      >
        {isSpeaking ? "🔊" : isOpen ? "✕" : "💬"}
      </button>

      {isOpen && (
        <div style={{
          position: "fixed", bottom: 96, right: 22,
          width: 400, height: 570,
          background: bg, borderRadius: 18,
          boxShadow: "0 12px 48px rgba(0,0,0,0.45)",
          zIndex: 10000, display: "flex", flexDirection: "column",
          overflow: "hidden", fontFamily: "'Inter', -apple-system, sans-serif",
          border: `1px solid ${darkMode ? "#2e2f35" : "#ddd"}`,
        }}>
          {/* Header */}
          <div style={{
            padding: "13px 16px", display: "flex", alignItems: "center",
            justifyContent: "space-between",
            background: "linear-gradient(135deg, #1a252f 0%, #0d1117 100%)",
            color: "#fff", flexShrink: 0,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{
                width: 36, height: 36, borderRadius: "50%",
                background: connected ? "#27ae60" : "#555",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 18, flexShrink: 0,
              }}>🛡</div>
              <div>
                <div style={{ fontWeight: 700, fontSize: 14 }}>Sarah</div>
                <div style={{ fontSize: 11, opacity: 0.7 }}>
                  {connected ? "🟢 Live" : "🔴 Offline"}
                </div>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              {isSpeaking && (
                <button onClick={stopSpeaking}
                  title="Stop speaking"
                  style={{ background: "none", border: "none", cursor: "pointer", color: "#ff9800", fontSize: 18 }}>
                  🔇
                </button>
              )}
              <label style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 12, cursor: "pointer" }}>
                <input type="checkbox" checked={alertsEnabled}
                  onChange={e => setAlertsEnabled(e.target.checked)}
                  style={{ width: 15, height: 15 }} />
                🔔
              </label>
            </div>
          </div>

          {/* Messages */}
          <div style={{
            flex: 1, overflowY: "auto", padding: "12px",
            display: "flex", flexDirection: "column", gap: 8,
            background: darkMode ? "#12131a" : "#f8f9fa",
          }}>
            {messages.map((msg, i) => (
              <MessageBubble key={i} msg={msg} darkMode={darkMode} />
            ))}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick actions */}
          <div style={{
            padding: "8px 10px 4px", background: bg,
            borderTop: `1px solid ${darkMode ? "#2e2f35" : "#eee"}`,
            display: "flex", gap: 5, flexWrap: "wrap", flexShrink: 0,
          }}>
            {quickActions.map((a, i) => (
              <button key={i} onClick={() => handleSend(a.cmd)}
                style={{
                  padding: "4px 10px", fontSize: 11,
                  border: `1px solid ${darkMode ? "#3a3b42" : "#ddd"}`,
                  borderRadius: 14, background: darkMode ? "#252629" : "#fff",
                  color: darkMode ? "#e8e8e8" : "#333", cursor: "pointer",
                }}>
                {a.label}
              </button>
            ))}
          </div>

          {/* Input row */}
          <div style={{
            padding: "8px 10px 12px", background: bg,
            display: "flex", gap: 8, alignItems: "center", flexShrink: 0,
          }}>
            <button onClick={toggleListening} title="Voice input"
              style={{
                width: 40, height: 40, borderRadius: "50%", border: "none",
                background: isListening ? "#e53935" : darkMode ? "#252629" : "#ecf0f1",
                color: isListening ? "#fff" : darkMode ? "#e8e8e8" : "#2c3e50",
                cursor: "pointer", fontSize: 17, flexShrink: 0, transition: "all 0.2s",
              }}>
              {isListening ? "⏹" : "🎤"}
            </button>
            <input
              value={input} onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && handleSend()}
              placeholder="Ask Sarah…"
              style={{
                flex: 1, padding: "10px 14px", borderRadius: 20,
                border: `1px solid ${darkMode ? "#3a3b42" : "#ddd"}`,
                background: darkMode ? "#252629" : "#fff",
                color: darkMode ? "#e8e8e8" : "#222",
                fontSize: 13, outline: "none",
              }}
            />
            <button onClick={() => handleSend()} disabled={!input.trim()}
              style={{
                width: 40, height: 40, borderRadius: "50%", border: "none",
                background: input.trim() ? "#27ae60" : darkMode ? "#252629" : "#bdc3c7",
                color: "#fff", cursor: input.trim() ? "pointer" : "default",
                fontSize: 17, flexShrink: 0, transition: "background 0.2s",
              }}>
              ➤
            </button>
          </div>
        </div>
      )}

      <style>{`
        @keyframes pulse {
          0%, 100% { transform: scale(1); box-shadow: 0 4px 18px rgba(0,0,0,.4); }
          50% { transform: scale(1.08); box-shadow: 0 6px 24px rgba(229,57,53,.6); }
        }
      `}</style>
    </>
  );
}

// ─── MessageBubble ───────────────────────────────────────────────────────────
function MessageBubble({ msg, darkMode }) {
  const isUser      = msg.role === "user";
  const isSystem    = msg.role === "system";
  const isAssistant = msg.role === "assistant";
  const sev         = msg.severity || "";
  const sevColour   = SEV_COLOUR[sev] || (sev === "voip" ? "#00BCD4" : null);

  const bg = isUser
    ? "#2d78d8"
    : isSystem
      ? (darkMode ? "#1e1010" : "#fff3f3")
      : (darkMode ? "#252629" : "#fff");

  const textCol = isUser ? "#fff" : isSystem ? (sevColour || "#cc4444") : (darkMode ? "#e8e8e8" : "#222");

  return (
    <div style={{
      alignSelf: isUser ? "flex-end" : isSystem ? "center" : "flex-start",
      maxWidth: "88%",
      background: bg,
      color: textCol,
      borderRadius: isSystem ? 16 : isUser ? "18px 18px 4px 18px" : "18px 18px 18px 4px",
      padding: "9px 14px",
      fontSize: 13,
      lineHeight: 1.45,
      boxShadow: isAssistant ? "0 1px 6px rgba(0,0,0,.12)" : "none",
      border: isSystem && sevColour ? `1px solid ${sevColour}33` : "none",
      whiteSpace: "pre-wrap",
    }}>
      {/* Severity badge for system messages */}
      {isSystem && sev && SEV_COLOUR[sev] && (
        <span style={{
          display: "inline-block", marginBottom: 3, marginRight: 6,
          background: sevColour, color: "#fff",
          borderRadius: 4, padding: "1px 6px", fontSize: 10, fontWeight: 700,
          verticalAlign: "middle",
        }}>
          {sev.toUpperCase()}
        </span>
      )}
      {/* AI badge */}
      {msg.isAi && (
        <span style={{
          display: "inline-block", marginBottom: 3, marginRight: 6,
          background: "#FF6F00", color: "#fff",
          borderRadius: 4, padding: "1px 6px", fontSize: 10, fontWeight: 700,
          verticalAlign: "middle",
        }}>
          AI
        </span>
      )}
      {/* Scheduled summary badge */}
      {msg.badge === "scheduled-summary" && (
        <div style={{ fontSize: 10, color: "#42A5F5", fontWeight: 700, marginBottom: 4 }}>
          📋 SCHEDULED THREAT SUMMARY
        </div>
      )}
      {msg.content}{msg.streaming && <span style={{ opacity: 0.6, animation: "pulse 0.8s infinite" }}>▍</span>}
      {/* Model source indicator */}
      {isAssistant && msg.source === "ollama" && !msg.streaming && (
        <div style={{ fontSize: 10, opacity: 0.45, marginTop: 4 }}>{msg.model || "ollama"}</div>
      )}
    </div>
  );
}
