import { useState, useEffect, useRef } from "react";
import axios from "axios";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell, RadialBarChart, RadialBar,
} from "recharts";
import "./App.css";

const API = "http://127.0.0.1:8000";

const SEV = {
  CRITICAL: { color: "#ef4444", glow: "#ef444466", bg: "#ef444412", rank: 0 },
  HIGH:     { color: "#f97316", glow: "#f9731666", bg: "#f9731612", rank: 1 },
  MEDIUM:   { color: "#eab308", glow: "#eab30866", bg: "#eab30812", rank: 2 },
  LOW:      { color: "#10b981", glow: "#10b98166", bg: "#10b98112", rank: 3 },
  INFO:     { color: "#06b6d4", glow: "#06b6d466", bg: "#06b6d412", rank: 4 },
  CLEAN:    { color: "#10b981", glow: "#10b98166", bg: "#10b98112", rank: 5 },
  UNKNOWN:  { color: "#475569", glow: "#47556966", bg: "#47556912", rank: 6 },
};

function Counter({ value }) {
  const [d, setD] = useState(0);
  useEffect(() => {
    const end = parseInt(value) || 0;
    if (end === 0) { setD(0); return; }
    let cur = 0;
    const step = Math.max(1, Math.floor(end / 18));
    const t = setInterval(() => {
      cur = Math.min(cur + step, end);
      setD(cur);
      if (cur >= end) clearInterval(t);
    }, 35);
    return () => clearInterval(t);
  }, [value]);
  return <>{d}</>;
}

function SevBadge({ level }) {
  const s = SEV[level] || SEV.UNKNOWN;
  return (
    <span style={{
      display: "inline-block", fontSize: 9, letterSpacing: "0.12em",
      padding: "3px 9px", borderRadius: 2,
      color: s.color, background: s.bg,
      border: `1px solid ${s.color}55`,
      boxShadow: `0 0 10px ${s.glow}`,
      fontFamily: "var(--mono)",
    }}>{level}</span>
  );
}

function HexCanvas() {
  const ref = useRef(null);
  useEffect(() => {
    const cv = ref.current; if (!cv) return;
    const ctx = cv.getContext("2d");
    let id, t = 0;
    const resize = () => { cv.width = cv.offsetWidth; cv.height = cv.offsetHeight; };
    resize();
    window.addEventListener("resize", resize);
    const hex = (x, y, r, a) => {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const ang = (Math.PI / 3) * i - Math.PI / 6;
        i === 0 ? ctx.moveTo(x + r * Math.cos(ang), y + r * Math.sin(ang))
                : ctx.lineTo(x + r * Math.cos(ang), y + r * Math.sin(ang));
      }
      ctx.closePath();
      ctx.strokeStyle = `rgba(6,182,212,${a})`;
      ctx.lineWidth = 0.6;
      ctx.stroke();
    };
    const draw = () => {
      ctx.clearRect(0, 0, cv.width, cv.height);
      t += 0.004;
      const r = 34;
      for (let row = -1; row < cv.height / (r * 1.5) + 2; row++) {
        for (let col = -1; col < cv.width / (r * 1.73) + 2; col++) {
          const x = col * r * 1.73 + (row % 2 ? r * 0.865 : 0);
          const y = row * r * 1.5;
          const w = (Math.sin(t + col * 0.28 + row * 0.18) + 1) / 2;
          hex(x, y, r - 2, w * 0.055 + 0.015);
        }
      }
      id = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(id); window.removeEventListener("resize", resize); };
  }, []);
  return <canvas ref={ref} style={{ position: "fixed", inset: 0, width: "100%", height: "100%", pointerEvents: "none", zIndex: 0 }} />;
}

function ScanOrb({ scanning, risk }) {
  const s = SEV[risk] || null;
  const clr = scanning ? "#f97316" : s ? s.color : "#06b6d4";
  const glow = scanning ? "#f9731660" : s ? s.glow : "#06b6d440";
  return (
    <div style={{ display: "flex", justifyContent: "center", marginBottom: 32 }}>
      <div style={{
        position: "relative", width: 180, height: 180,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        {/* outer rings */}
        {[1, 0.7, 0.45].map((op, i) => (
          <div key={i} style={{
            position: "absolute",
            width: 180 - i * 36, height: 180 - i * 36,
            borderRadius: "50%",
            border: `1px solid ${clr}`,
            opacity: op * (scanning ? 1 : 0.35),
            boxShadow: i === 0 ? `0 0 24px ${glow}, inset 0 0 24px ${glow}` : "none",
            animation: scanning ? `orbPulse ${1.2 + i * 0.4}s ease-in-out infinite` : "none",
          }} />
        ))}
        {/* radar sweep */}
        {scanning && (
          <div style={{
            position: "absolute", width: 144, height: 144, borderRadius: "50%", overflow: "hidden",
          }}>
            <div style={{
              position: "absolute", top: "50%", left: "50%",
              width: "50%", height: 1,
              background: `linear-gradient(90deg, transparent, ${clr})`,
              transformOrigin: "0 50%",
              animation: "radarSpin 1.8s linear infinite",
            }} />
          </div>
        )}
        {/* core */}
        <div style={{
          width: 100, height: 100, borderRadius: "50%",
          background: `radial-gradient(circle, ${clr}22 0%, transparent 70%)`,
          border: `1px solid ${clr}66`,
          display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center",
          boxShadow: `0 0 30px ${glow}`,
        }}>
          {scanning ? (
            <>
              <div style={{ fontSize: 10, color: clr, letterSpacing: "0.2em", opacity: 0.8 }}>SCAN</div>
              <div style={{ fontSize: 10, color: clr, letterSpacing: "0.2em" }}>ACTIVE</div>
            </>
          ) : risk ? (
            <>
              <div style={{ fontSize: 8, color: clr, letterSpacing: "0.2em", opacity: 0.7, marginBottom: 2 }}>RISK</div>
              <div style={{ fontSize: risk.length > 6 ? 11 : 14, color: clr, fontFamily: "var(--sans)", fontWeight: 700, letterSpacing: "0.05em", textAlign: "center", textShadow: `0 0 12px ${clr}` }}>{risk}</div>
            </>
          ) : (
            <>
              <div style={{ fontSize: 22, color: clr, opacity: 0.6 }}>⬡</div>
              <div style={{ fontSize: 8, color: clr, letterSpacing: "0.2em", opacity: 0.5, marginTop: 2 }}>READY</div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [target,   setTarget]   = useState("");
  const [mode,     setMode]     = useState("basic");
  const [scanning, setScanning] = useState(false);
  const [report,   setReport]   = useState(null);
  const [history,  setHistory]  = useState([]);
  const [stats,    setStats]    = useState(null);
  const [online,   setOnline]   = useState(false);
  const [error,    setError]    = useState("");
  const [view,     setView]     = useState("scan");
  const [elapsed,  setElapsed]  = useState(0);
  const [logs,     setLogs]     = useState([]);
  const logRef = useRef(null);

  const log = (msg, type = "info") =>
    setLogs(l => [...l.slice(-40), { msg, type, t: new Date().toLocaleTimeString() }]);

  useEffect(() => {
    axios.get(`${API}/health`)
      .then(() => { setOnline(true); log("API server connected", "ok"); })
      .catch(() => { setOnline(false); log("API offline — run: python api.py", "err"); });
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  useEffect(() => {
    if (!scanning) { setElapsed(0); return; }
    const id = setInterval(() => setElapsed(s => s + 1), 1000);
    return () => clearInterval(id);
  }, [scanning]);

  useEffect(() => {
    if (online) { reload(); }
  }, [online]);

  async function reload() {
    try { const r = await axios.get(`${API}/scans/history`); setHistory(r.data.scans || []); } catch {}
    try { const r = await axios.get(`${API}/scans/stats`);   setStats(r.data); } catch {}
  }

  async function scan() {
    if (!target.trim()) { setError("Enter a target."); return; }
    setError(""); setScanning(true); setReport(null);
    log(`Initiating ${mode} scan → ${target.trim()}`, "info");
    try {
      const res = await axios.post(`${API}/scan`, { target: target.trim(), scan_type: mode });
      const r = res.data.data;
      setReport(r);
      log(`Scan complete — ${r.summary.open_ports} open ports`, "ok");
      log(`Overall risk: ${r.summary.overall_risk}`,
        ["CRITICAL","HIGH"].includes(r.summary.overall_risk) ? "err" : "ok");
      await reload();
      setView("results");
    } catch (e) {
      const msg = e.response?.data?.detail || "Scan failed.";
      setError(msg); log(msg, "err");
    } finally { setScanning(false); }
  }

  const risk    = report?.summary?.overall_risk || null;
  const riskS   = SEV[risk] || SEV.UNKNOWN;
  const allPorts = report?.hosts?.flatMap(h => h.open_ports) || [];
  const chartData = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    .map(s => ({ name: s, count: allPorts.filter(p => p.severity === s).length }))
    .filter(d => d.count > 0);

  const NAV = [
    { id: "scan",    label: "Scanner",  icon: "◈" },
    { id: "results", label: "Results",  icon: "▦" },
    { id: "history", label: "History",  icon: "≡" },
    { id: "modules", label: "Modules",  icon: "⬡" },
  ];

  return (
    <div className="app">
      <HexCanvas />

      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="sb-logo">
          <div className="sb-hex">⬡</div>
          <div>
            <div className="sb-name">SafeNet</div>
            <div className="sb-country">GHANA</div>
          </div>
        </div>

        <nav className="sb-nav">
          {NAV.map(n => (
            <button key={n.id} className={`sb-btn ${view === n.id ? "sb-active" : ""}`}
              onClick={() => setView(n.id)}>
              <span className="sb-icon">{n.icon}</span>
              <span className="sb-lbl">{n.label}</span>
              {n.id === "results" && risk && (
                <span className="sb-pip" style={{ background: riskS.color, boxShadow: `0 0 6px ${riskS.glow}` }} />
              )}
            </button>
          ))}
        </nav>

        <div className="sb-foot">
          <div className={`api-chip ${online ? "api-on" : "api-off"}`}>
            <span className="api-dot" /> {online ? "API LIVE" : "API DOWN"}
          </div>
          <div className="sb-author">Patrick Idan</div>
          <div className="sb-sub">GCTU · Cybersecurity</div>
        </div>
      </aside>

      {/* CONTENT */}
      <main className="content">

        {/* ── SCANNER ─────────────────────────────────── */}
        {view === "scan" && (
          <div className="panel fade-in">
            <div className="panel-head">
              <div className="ph-title">Vulnerability Scanner</div>
              <div className="ph-sub">Module 1 · nmap engine · FastAPI</div>
            </div>

            <div className="scan-grid">
              <div className="scan-col-left">
                <ScanOrb scanning={scanning} risk={risk} />

                <label className="field-lbl">TARGET IP / HOSTNAME</label>
                <div className="inp-row">
                  <span className="inp-pre">▶</span>
                  <input className="inp" placeholder="e.g.  192.168.1.1"
                    value={target} onChange={e => setTarget(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && !scanning && scan()}
                    disabled={scanning} />
                </div>

                <label className="field-lbl" style={{ marginTop: 20 }}>SCAN MODE</label>
                <div className="mode-row">
                  {[
                    { id: "basic",   name: "BASIC",   info: "~60s · top 100 ports"   },
                    { id: "version", name: "VERSION", info: "~90s · detect software"  },
                    { id: "full",    name: "FULL",    info: "~5min · all 65535 ports" },
                  ].map(m => (
                    <button key={m.id}
                      className={`mode-btn ${mode === m.id ? "mode-sel" : ""}`}
                      onClick={() => setMode(m.id)} disabled={scanning}>
                      <div className="mode-name">{m.name}</div>
                      <div className="mode-info">{m.info}</div>
                    </button>
                  ))}
                </div>

                {error && <div className="err-box">⚠ {error}</div>}

                <button className={`fire-btn ${scanning ? "fire-busy" : ""}`}
                  onClick={scan} disabled={scanning || !online}>
                  {scanning
                    ? <><span className="spin" /> SCANNING · {elapsed}s</>
                    : !online ? "⚠  START api.py FIRST"
                    : "▶  INITIATE SCAN"}
                </button>

                {scanning && (
                  <div className="progress-track">
                    <div className="progress-fill" />
                  </div>
                )}
              </div>

              <div className="scan-col-right">
                {/* Session stats */}
                {stats && stats.total_scans > 0 && (
                  <div className="mini-grid">
                    {[
                      { v: stats.total_scans,               l: "TOTAL SCANS",   c: "#06b6d4" },
                      { v: stats.total_ports_found,         l: "PORTS FOUND",   c: "#f97316" },
                      { v: stats.risk_breakdown?.CRITICAL || 0, l: "CRITICAL",  c: "#ef4444" },
                    ].map((s, i) => (
                      <div key={i} className="mini-card" style={{ "--mc": s.c }}>
                        <div className="mc-val" style={{ color: s.c }}><Counter value={s.v} /></div>
                        <div className="mc-lbl">{s.l}</div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Log */}
                <div className="log-box">
                  <div className="log-head">
                    <span>// SYSTEM LOG</span>
                    <span style={{ color: "#334155", fontSize: 10 }}>{logs.length} entries</span>
                  </div>
                  <div className="log-body" ref={logRef}>
                    {logs.length === 0
                      ? <div className="log-empty">Waiting for activity...</div>
                      : logs.map((l, i) => (
                        <div key={i} className={`log-line log-${l.type}`}>
                          <span className="log-t">{l.t}</span>
                          <span>{l.msg}</span>
                        </div>
                      ))
                    }
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── RESULTS ─────────────────────────────────── */}
        {view === "results" && (
          <div className="panel fade-in">
            <div className="panel-head">
              <div className="ph-title">Scan Results</div>
              <div className="ph-sub">
                {report
                  ? `${report.scan_metadata.target} · ${new Date(report.scan_metadata.timestamp).toLocaleString()}`
                  : "No scan run yet"}
              </div>
            </div>

            {!report ? (
              <div className="empty">
                <div className="empty-ico">◈</div>
                <div className="empty-title">No results yet</div>
                <div className="empty-sub">Run a scan from the Scanner tab</div>
                <button className="ghost-btn" onClick={() => setView("scan")}>→ Go to Scanner</button>
              </div>
            ) : (
              <>
                {/* Hero */}
                <div className="risk-hero" style={{ "--rc": riskS.color, "--rg": riskS.glow, "--rb": riskS.bg }}>
                  <div className="rh-left">
                    <div className="rh-eyebrow">THREAT ASSESSMENT</div>
                    <div className="rh-level">{risk}</div>
                    <div className="rh-target">{report.scan_metadata.target}</div>
                    <div className="rh-time">{new Date(report.scan_metadata.timestamp).toLocaleString()}</div>
                  </div>
                  <div className="rh-right">
                    <div className="rh-stat"><Counter value={report.summary.open_ports} /></div>
                    <div className="rh-stat-lbl">OPEN PORTS</div>
                  </div>
                </div>

                {/* Stat cards */}
                <div className="rs-grid">
                  {[
                    { l: "HOSTS UP",   v: report.summary.total_hosts,    c: "#06b6d4" },
                    { l: "OPEN PORTS", v: report.summary.open_ports,     c: "#f97316" },
                    { l: "CRITICAL",   v: report.summary.critical_count, c: "#ef4444" },
                    { l: "HIGH",       v: report.summary.high_count,     c: "#f97316" },
                    { l: "MEDIUM",     v: report.summary.medium_count,   c: "#eab308" },
                    { l: "LOW",        v: report.summary.low_count,      c: "#10b981" },
                  ].map((s, i) => (
                    <div key={i} className="rs-card" style={{ "--sc": s.c }}>
                      <div className="rs-val" style={{ color: s.c }}><Counter value={s.v} /></div>
                      <div className="rs-lbl">{s.l}</div>
                    </div>
                  ))}
                </div>

                {/* Chart */}
                {chartData.length > 0 && (
                  <div className="glass-box">
                    <div className="gb-title">PORT SEVERITY BREAKDOWN</div>
                    <ResponsiveContainer width="100%" height={160}>
                      <BarChart data={chartData} barSize={48}>
                        <XAxis dataKey="name" tick={{ fill: "#475569", fontSize: 10, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
                        <YAxis tick={{ fill: "#475569", fontSize: 10, fontFamily: "monospace" }} axisLine={false} tickLine={false} allowDecimals={false} />
                        <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", color: "#e2e8f0", fontFamily: "monospace", fontSize: 12, borderRadius: 4 }} cursor={{ fill: "#ffffff05" }} />
                        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                          {chartData.map((d, i) => (
                            <Cell key={i} fill={SEV[d.name]?.color || "#555"} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}

                {/* Port tables */}
                {report.hosts.map((host, hi) => (
                  <div key={hi} className="glass-box">
                    <div className="gb-title" style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      HOST: {host.ip}
                      <span style={{ color: "#10b981", fontSize: 10 }}>● {host.state.toUpperCase()}</span>
                      <SevBadge level={host.host_risk} />
                    </div>
                    {host.open_ports.length === 0 ? (
                      <div style={{ fontSize: 12, color: "#10b981", padding: "12px 0" }}>✓ No vulnerable ports detected.</div>
                    ) : (
                      <table className="ft">
                        <thead>
                          <tr>{["PORT","SERVICE","PRODUCT","SEVERITY","DESCRIPTION"].map(h => <th key={h}>{h}</th>)}</tr>
                        </thead>
                        <tbody>
                          {host.open_ports.map((p, pi) => {
                            const ps = SEV[p.severity] || SEV.UNKNOWN;
                            return (
                              <tr key={pi} className="ft-row" style={{ "--pc": ps.color, "--pb": ps.bg }}>
                                <td className="ft-port">{p.port}<span>/{p.protocol}</span></td>
                                <td style={{ color: "#e2e8f0" }}>{p.service}</td>
                                <td style={{ color: "#64748b", fontSize: 11 }}>{p.product || "—"}</td>
                                <td><SevBadge level={p.severity} /></td>
                                <td style={{ color: "#475569", fontSize: 11 }}>{p.description}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    )}
                  </div>
                ))}
                <button className="ghost-btn" style={{ marginTop: 8 }} onClick={() => setView("scan")}>▶ New Scan</button>
              </>
            )}
          </div>
        )}

        {/* ── HISTORY ─────────────────────────────────── */}
        {view === "history" && (
          <div className="panel fade-in">
            <div className="panel-head">
              <div className="ph-title">Scan History</div>
              <div className="ph-sub">{history.length} scans this session</div>
            </div>
            {history.length === 0 ? (
              <div className="empty">
                <div className="empty-ico">≡</div>
                <div className="empty-title">No history yet</div>
                <div className="empty-sub">Completed scans appear here</div>
              </div>
            ) : (
              <div className="glass-box">
                <table className="ft">
                  <thead>
                    <tr>{["#","TARGET","TIMESTAMP","PORTS","RISK"].map(h => <th key={h}>{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {history.map((s, i) => {
                      const hs = SEV[s.risk] || SEV.UNKNOWN;
                      return (
                        <tr key={i} className="ft-row" style={{ "--pc": hs.color, "--pb": hs.bg }}>
                          <td style={{ color: "#475569" }}>{i + 1}</td>
                          <td className="ft-port">{s.target}</td>
                          <td style={{ color: "#64748b", fontSize: 11 }}>{new Date(s.timestamp).toLocaleString()}</td>
                          <td style={{ color: "#e2e8f0" }}>{s.open_ports}</td>
                          <td><SevBadge level={s.risk} /></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── MODULES ─────────────────────────────────── */}
        {view === "modules" && (
          <div className="panel fade-in">
            <div className="panel-head">
              <div className="ph-title">System Modules</div>
              <div className="ph-sub">SafeNet Ghana · Build roadmap · GCTU Cybersecurity</div>
            </div>
            <div className="mod-grid">
              {[
                { name: "Vulnerability Scanner", status: "live",     color: "#10b981", icon: "◈", stack: ["Python","nmap","FastAPI"],          desc: "Scans networks for open ports and known vulnerabilities. Severity-scored JSON reports.",      level: "Level 100 ✓" },
                { name: "React Dashboard",        status: "live",     color: "#10b981", icon: "▦", stack: ["React.js","Recharts","Axios"],      desc: "Unified web dashboard with real-time results, charts, history, and module overview.",         level: "Level 100 ✓" },
                { name: "WiFi Intrusion Detection",status:"building",  color: "#06b6d4", icon: "◉", stack: ["Python","Scapy","Aircrack-ng"],    desc: "Detects rogue APs, deauth attacks, and ARP spoofing on the network in real-time.",            level: "Level 200" },
                { name: "PostgreSQL Database",    status: "building", color: "#06b6d4", icon: "▦", stack: ["PostgreSQL","SQLAlchemy"],          desc: "Persistent storage for all scan results, alerts, user accounts, and threat history.",          level: "Level 200" },
                { name: "CCTV Network Monitor",   status: "planned",  color: "#a855f7", icon: "⬡", stack: ["OpenCV","ONVIF","RTSP"],           desc: "Monitors IP camera traffic for unauthorized access and bandwidth anomalies.",                   level: "Level 200" },
                { name: "Flutter Mobile App",     status: "planned",  color: "#f97316", icon: "◈", stack: ["Flutter","Dart","Firebase FCM"],   desc: "Cross-platform Android + iOS app with push notifications and live scan triggering.",            level: "Level 300" },
              ].map((m, i) => (
                <div key={i} className="mod-card" style={{ "--mc": m.color }}>
                  <div className="mc-head">
                    <span style={{ color: m.color, fontSize: 18 }}>{m.icon}</span>
                    <span className={`mc-status mc-${m.status}`}>
                      {m.status === "live" ? "● LIVE" : m.status === "building" ? "◌ BUILDING" : "○ PLANNED"}
                    </span>
                  </div>
                  <div className="mc-name">{m.name}</div>
                  <div className="mc-desc">{m.desc}</div>
                  <div className="mc-stack">
                    {m.stack.map((t, ti) => (
                      <span key={ti} className="st-tag">{t}</span>
                    ))}
                  </div>
                  <div className="mc-level">{m.level}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
