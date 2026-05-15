import { useState, useEffect, useRef } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000";
// ── Axios interceptors ─────────────────────────────────────────────────────
// Automatically attach JWT token to every request
axios.interceptors.request.use(config => {
  const token = localStorage.getItem("safenet_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});
// Auto-logout on 401
axios.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem("safenet_token");
      localStorage.removeItem("safenet_user");
      window.location.reload();
    }
    return Promise.reject(err);
  }
);

// ── Simulated Data Generators ──────────────────────────────────────────────
const VULN_TEMPLATES = [
  { id: "CVE-2024-1234", name: "OpenSSH Auth Bypass",    host: "192.168.1.10", port: 22,   severity: "CRITICAL", cvss: 9.8, service: "SSH"   },
  { id: "CVE-2024-5678", name: "Apache Log4j RCE",       host: "192.168.1.22", port: 8080, severity: "HIGH",     cvss: 8.1, service: "HTTP"  },
  { id: "CVE-2023-4499", name: "SMB Null Session",       host: "192.168.1.15", port: 445,  severity: "HIGH",     cvss: 7.5, service: "SMB"   },
  { id: "CVE-2024-2222", name: "MySQL Weak Auth",        host: "192.168.1.30", port: 3306, severity: "MEDIUM",   cvss: 6.2, service: "MySQL" },
  { id: "CVE-2023-9900", name: "TLS 1.0 Deprecated",    host: "192.168.1.44", port: 443,  severity: "MEDIUM",   cvss: 5.9, service: "HTTPS" },
  { id: "CVE-2024-0001", name: "Redis No Auth",          host: "192.168.1.55", port: 6379, severity: "HIGH",     cvss: 7.8, service: "Redis" },
  { id: "CVE-2022-0778", name: "OpenSSL Infinite Loop",  host: "192.168.1.10", port: 443,  severity: "LOW",      cvss: 3.1, service: "HTTPS" },
  { id: "CVE-2024-3333", name: "FTP Anonymous Login",    host: "192.168.1.60", port: 21,   severity: "MEDIUM",   cvss: 5.3, service: "FTP"   },
];

const WIFI_ALERT_TEMPLATES = [
  { type: "DEAUTH_FLOOD",   device: "AA:BB:CC:DD:EE:FF", ssid: "CorpNet-5G",      channel: 6,  detail: "Deauthentication flood — attacker forcing clients off network" },
  { type: "EVIL_TWIN",      device: "11:22:33:44:55:66", ssid: "CorpNet-5G",      channel: 11, detail: "Evil Twin AP — fake network cloning legitimate SSID" },
  { type: "ROGUE_AP",       device: "DE:AD:BE:EF:00:01", ssid: "FreeWifi_GH",     channel: 1,  detail: "Unauthorized AP detected — not in whitelist" },
  { type: "MITM_ARP_SPOOF", device: "BE:EF:CA:FE:11:22", ssid: "CorpNet-5G",      channel: 6,  detail: "ARP spoofing — Man-in-the-Middle attack in progress" },
  { type: "MAC_SPOOF",      device: "02:AB:CD:EF:00:11", ssid: "—",               channel: 6,  detail: "Locally administered MAC — possible MAC spoofing" },
  { type: "WPS_BRUTE",      device: "CA:FE:BA:BE:00:FF", ssid: "GuestWifi",       channel: 6,  detail: "WPS PIN brute force — router PIN under attack" },
  { type: "PMKID_HARVEST",  device: "FA:CE:B0:0C:00:AA", ssid: "CorpNet-2G",      channel: 3,  detail: "PMKID harvest — offline WPA2 password crack prep" },
  { type: "EAVESDROPPING",  device: "C0:FF:EE:00:11:22", ssid: "OpenNet-GH",      channel: 11, detail: "Open unencrypted network — traffic visible to sniffers" },
  { type: "PROBE_SWEEP",    device: "DE:AD:00:00:BE:EF", ssid: "—",               channel: 1,  detail: "Passive probe sweep — active WiFi reconnaissance" },
  { type: "BEACON_FLOOD",   device: "FF:EE:DD:CC:BB:AA", ssid: "CorpNet-5G",      channel: 6,  detail: "Beacon flood attack — network disruption attempt" },
];

const CCTV_FEEDS = [
  { id: "CAM-01", name: "Main Entrance",  location: "Building A", status: "online"   },
  { id: "CAM-02", name: "Server Room",    location: "B2 Floor",   status: "online"   },
  { id: "CAM-03", name: "Parking Lot N",  location: "Exterior",   status: "online"   },
  { id: "CAM-04", name: "Roof Access",    location: "Rooftop",    status: "degraded" },
  { id: "CAM-05", name: "Reception",      location: "Building B", status: "online"   },
  { id: "CAM-06", name: "Storage Room",   location: "B1 Floor",   status: "offline"  },
];

const CCTV_ALERT_TEMPLATES = [
  { cam: "CAM-02", type: "UNAUTHORIZED_ACCESS", detail: "Motion in server room outside business hours" },
  { cam: "CAM-01", type: "STREAM_TAMPERING",    detail: "RTSP stream replay attack detected" },
  { cam: "CAM-04", type: "BANDWIDTH_SPIKE",     detail: "Unusual egress bandwidth spike on camera subnet" },
  { cam: "CAM-03", type: "CREDENTIAL_SPRAY",    detail: "Multiple failed VMS login attempts" },
  { cam: "CAM-06", type: "FEED_INTERRUPTED",    detail: "Camera feed interrupted — possible physical tampering" },
];

const rand = (arr) => arr[Math.floor(Math.random() * arr.length)];
const uid  = () => Math.random().toString(36).slice(2, 8).toUpperCase();

function genWifiAlert()  { const t = rand(WIFI_ALERT_TEMPLATES);  return { ...t, id: uid(), ts: new Date(), strength: Math.floor(Math.random()*60)-90 }; }
function genCctvAlert()  { const t = rand(CCTV_ALERT_TEMPLATES);  return { ...t, id: uid(), ts: new Date() }; }

// ── Severity Colours ───────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { bg: "#ff2d2d22", border: "#ff2d2d", text: "#ff6b6b", dot: "#ff2d2d" },
  HIGH:     { bg: "#ff8c0022", border: "#ff8c00", text: "#ffb347", dot: "#ff8c00" },
  MEDIUM:   { bg: "#ffd70022", border: "#ffd700", text: "#ffe55c", dot: "#ffd700" },
  LOW:      { bg: "#00bfff22", border: "#00bfff", text: "#67d9ff", dot: "#00bfff" },
};
const WIFI_SEV = {
  DEAUTH_FLOOD: SEV.CRITICAL, EVIL_TWIN: SEV.CRITICAL, MITM_ARP_SPOOF: SEV.CRITICAL,
  PMKID_HARVEST: SEV.CRITICAL, ROGUE_AP: SEV.HIGH, MAC_SPOOF: SEV.HIGH,
  WPS_BRUTE: SEV.HIGH, EAVESDROPPING: SEV.HIGH, DISASSOC_FLOOD: SEV.HIGH,
  PROBE_SWEEP: SEV.MEDIUM, BEACON_FLOOD: SEV.MEDIUM, ARP_SPOOF: SEV.CRITICAL,
};
const CCTV_SEV = {
  UNAUTHORIZED_ACCESS: SEV.CRITICAL, STREAM_TAMPERING: SEV.HIGH,
  BANDWIDTH_SPIKE: SEV.MEDIUM, CREDENTIAL_SPRAY: SEV.HIGH, FEED_INTERRUPTED: SEV.HIGH,
};

// ── Tiny reusable components ───────────────────────────────────────────────
function Badge({ label, sev }) {
  const s = sev || SEV.MEDIUM;
  return (
    <span style={{
      background: s.bg, border: `1px solid ${s.border}`, color: s.text,
      fontSize: 9, fontFamily: "'Share Tech Mono', monospace", fontWeight: 700,
      padding: "2px 7px", borderRadius: 3, letterSpacing: 1, whiteSpace: "nowrap"
    }}>{label}</span>
  );
}

function PulsingDot({ color = "#00ff88", size = 8 }) {
  return (
    <span style={{ position: "relative", display: "inline-block", width: size, height: size }}>
      <span style={{ position: "absolute", inset: 0, borderRadius: "50%", background: color, opacity: 0.3, animation: "ping 1.4s ease-out infinite" }} />
      <span style={{ position: "absolute", inset: 0, borderRadius: "50%", background: color }} />
    </span>
  );
}

function SectionHeader({ icon, title, count, color = "#00ff88" }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
      <span style={{ fontSize: 18 }}>{icon}</span>
      <span style={{ fontFamily: "'Orbitron', sans-serif", fontSize: 12, color, letterSpacing: 2, fontWeight: 700, textTransform: "uppercase" }}>
        {title}
      </span>
      {count !== undefined && (
        <span style={{
          marginLeft: "auto", background: color + "22", border: `1px solid ${color}`,
          color, fontSize: 10, fontFamily: "'Share Tech Mono', monospace", padding: "1px 8px", borderRadius: 3
        }}>{count}</span>
      )}
    </div>
  );
}

function Panel({ children, style = {} }) {
  return (
    <div style={{
      background: "rgba(10,18,30,0.85)", border: "1px solid rgba(0,255,136,0.15)",
      borderRadius: 8, padding: 18, backdropFilter: "blur(8px)",
      boxShadow: "0 0 30px rgba(0,255,136,0.04), inset 0 1px 0 rgba(255,255,255,0.04)",
      ...style
    }}>{children}</div>
  );
}

function ScanProgress({ progress, phase }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#00ff88" }}>{phase}</span>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#67d9ff" }}>{progress}%</span>
      </div>
      <div style={{ height: 4, background: "rgba(0,255,136,0.1)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{
          height: "100%", width: `${progress}%`, borderRadius: 2,
          background: "linear-gradient(90deg, #00ff88, #00bfff)",
          transition: "width 0.3s ease", boxShadow: "0 0 8px #00ff88"
        }} />
      </div>
    </div>
  );
}

// ── LOGIN PAGE ─────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [showPass, setShowPass] = useState(false);
  const [dots,     setDots]     = useState(0);

  useEffect(() => {
    if (!loading) return;
    const id = setInterval(() => setDots(d => (d + 1) % 4), 380);
    return () => clearInterval(id);
  }, [loading]);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!username || !password) { setError("Enter username and password."); return; }
    setError(""); setLoading(true);
    try {
      const form = new FormData();
      form.append("username", username);
      form.append("password", password);
      const res = await axios.post(`${API}/auth/login`, form, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      localStorage.setItem("safenet_token", res.data.access_token);
      localStorage.setItem("safenet_user",  JSON.stringify({ username: res.data.username, full_name: res.data.full_name, role: res.data.role }));
      onLogin(res.data);
    } catch (e) {
      setError(e.response?.data?.detail || "Login failed. Check credentials.");
    } finally { setLoading(false); }
  }

  return (
    <div style={{
      minHeight: "100vh", background: "#040810", display: "flex",
      alignItems: "center", justifyContent: "center",
      backgroundImage: `
        radial-gradient(ellipse 60% 40% at 20% 20%, rgba(0,255,136,0.04) 0%, transparent 60%),
        radial-gradient(ellipse 50% 50% at 80% 80%, rgba(103,217,255,0.03) 0%, transparent 60%),
        repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0,255,136,0.015) 39px, rgba(0,255,136,0.015) 40px),
        repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,255,136,0.015) 39px, rgba(0,255,136,0.015) 40px)
      `,
      fontFamily: "'Share Tech Mono', monospace"
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap');
        * { box-sizing: border-box; }
        @keyframes ping { 0%{transform:scale(1);opacity:.5} 75%,100%{transform:scale(2.2);opacity:0} }
        @keyframes loginIn { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
        @keyframes hexSpin { 0%,100%{filter:drop-shadow(0 0 8px #00ff8844)} 50%{filter:drop-shadow(0 0 20px #00ff88aa)} }
        @keyframes errShake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-6px)} 75%{transform:translateX(6px)} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
      `}</style>

      <div style={{
        width: "100%", maxWidth: 400, padding: "36px 32px",
        background: "rgba(10,18,30,0.95)", border: "1px solid rgba(0,255,136,0.2)",
        borderTop: "2px solid #00ff88", borderRadius: 10,
        boxShadow: "0 0 60px rgba(0,255,136,0.1), 0 40px 80px rgba(0,0,0,0.6)",
        animation: "loginIn 0.45s cubic-bezier(0.16,1,0.3,1) both"
      }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 24 }}>
          <span style={{ fontSize: 34, color: "#00ff88", animation: "hexSpin 3s ease-in-out infinite" }}>⬡</span>
          <div>
            <div style={{ fontFamily: "'Orbitron', sans-serif", fontWeight: 900, fontSize: 18, color: "#00ff88", letterSpacing: 3 }}>SAFENET</div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#335", letterSpacing: 3, marginTop: 2 }}>INTEGRATED SECURITY OPERATIONS</div>
          </div>
        </div>

        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#334", letterSpacing: 1, marginBottom: 28, paddingBottom: 20, borderBottom: "1px solid rgba(0,255,136,0.1)" }}>
          GHANA · GCTU CYBERSECURITY · PATRICK IDAN
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#445", letterSpacing: 2, marginBottom: 7 }}>USERNAME</div>
            <div style={{
              display: "flex", alignItems: "center",
              background: "rgba(0,255,136,0.05)", border: "1px solid rgba(0,255,136,0.2)",
              borderLeft: "3px solid #00ff88", borderRadius: 4,
            }}>
              <span style={{ padding: "0 10px", color: "#00ff88", fontSize: 12, opacity: 0.6 }}>◈</span>
              <input
                type="text" value={username} onChange={e => setUsername(e.target.value)}
                placeholder="admin" disabled={loading}
                style={{
                  flex: 1, background: "none", border: "none", outline: "none",
                  color: "#e0e0e0", fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 12, padding: "11px 8px 11px 0"
                }} />
            </div>
          </div>

          <div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#445", letterSpacing: 2, marginBottom: 7 }}>PASSWORD</div>
            <div style={{
              display: "flex", alignItems: "center",
              background: "rgba(0,255,136,0.05)", border: "1px solid rgba(0,255,136,0.2)",
              borderLeft: "3px solid #00ff88", borderRadius: 4,
            }}>
              <span style={{ padding: "0 10px", color: "#00ff88", fontSize: 12, opacity: 0.6 }}>▦</span>
              <input
                type={showPass ? "text" : "password"} value={password} onChange={e => setPassword(e.target.value)}
                placeholder="••••••••" disabled={loading}
                style={{
                  flex: 1, background: "none", border: "none", outline: "none",
                  color: "#e0e0e0", fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 12, padding: "11px 8px 11px 0"
                }} />
              <button type="button" onClick={() => setShowPass(s => !s)} style={{
                background: "none", border: "none", color: "#334", fontFamily: "'Share Tech Mono', monospace",
                fontSize: 9, padding: "0 12px", cursor: "pointer", letterSpacing: 1
              }}>{showPass ? "HIDE" : "SHOW"}</button>
            </div>
          </div>

          {error && (
            <div style={{
              background: "rgba(255,45,45,0.1)", border: "1px solid rgba(255,45,45,0.3)",
              borderRadius: 4, padding: "9px 12px", color: "#ff6b6b",
              fontFamily: "'Share Tech Mono', monospace", fontSize: 11,
              animation: "errShake 0.35s ease"
            }}>⚠ {error}</div>
          )}

          <button type="submit" disabled={loading} style={{
            width: "100%", padding: 14,
            background: loading ? "rgba(255,107,107,0.1)" : "rgba(0,255,136,0.12)",
            border: `1px solid ${loading ? "rgba(255,107,107,0.4)" : "rgba(0,255,136,0.5)"}`,
            color: loading ? "#ff8c00" : "#00ff88",
            fontFamily: "'Orbitron', sans-serif", fontSize: 11, fontWeight: 700,
            letterSpacing: 2, borderRadius: 5, cursor: loading ? "not-allowed" : "pointer",
            transition: "all 0.2s", marginTop: 4,
            animation: loading ? "blink 1.2s ease-in-out infinite" : "none"
          }}>
            {loading ? `AUTHENTICATING${".".repeat(dots)}` : "▶  ACCESS SYSTEM"}
          </button>
        </form>

        {/* Demo credentials */}
        <div style={{
          marginTop: 24, padding: "12px 14px",
          background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.05)",
          borderRadius: 5
        }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#223", letterSpacing: 2, marginBottom: 9 }}>
            // DEMO CREDENTIALS
          </div>
          {[
            { role: "ADMIN",  cred: "admin / admin123",   color: "#ff6b6b" },
            { role: "VIEWER", cred: "viewer / viewer123", color: "#67d9ff" },
          ].map(r => (
            <div key={r.role} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 5 }}>
              <span style={{
                fontFamily: "'Share Tech Mono', monospace", fontSize: 8,
                color: r.color, background: r.color + "15",
                border: `1px solid ${r.color}30`, padding: "2px 7px", borderRadius: 2,
                minWidth: 48, textAlign: "center"
              }}>{r.role}</span>
              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#334" }}>{r.cred}</span>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 18, textAlign: "center", fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#223", letterSpacing: 1 }}>
          SAFENET GHANA v0.4.0 · FINAL YEAR PROJECT · GCTU
        </div>
      </div>
    </div>
  );
}

// ── VULN SCANNER (connected to real API) ──────────────────────────────────
function VulnScanner({ authUser }) {
  const [scanning,   setScanning]   = useState(false);
  const [progress,   setProgress]   = useState(0);
  const [phase,      setPhase]      = useState("IDLE");
  const [vulns,      setVulns]      = useState([]);
  const [target,     setTarget]     = useState("192.168.1.1");
  const [scanType,   setScanType]   = useState("basic");
  const [apiOnline,  setApiOnline]  = useState(false);
  const [useReal,    setUseReal]    = useState(false);
  const [error,      setError]      = useState("");
  const intervalRef = useRef(null);

  const phases = ["HOST DISCOVERY", "PORT SCANNING", "SERVICE DETECTION", "VULN MATCHING", "REPORT GENERATION"];

  useEffect(() => {
    axios.get(`${API}/health`).then(() => setApiOnline(true)).catch(() => setApiOnline(false));
  }, []);

  // Convert real API port data → display format
  function convertRealResults(report) {
    return report.hosts.flatMap(host =>
      host.open_ports.map(p => ({
        id:       `PORT-${p.port}`,
        name:     p.description.slice(0, 38),
        host:     host.ip,
        port:     p.port,
        severity: p.severity === "INFO" ? "LOW" : p.severity,
        cvss:     { CRITICAL: 9.5, HIGH: 7.5, MEDIUM: 5.5, LOW: 3.0, INFO: 1.0 }[p.severity] || 3.0,
        service:  p.service,
      }))
    );
  }

  async function startRealScan() {
    if (authUser?.role !== "admin") { setError("Admin role required to run scans."); return; }
    setError(""); setScanning(true); setProgress(0); setVulns([]);
    let p = 0;
    // Animate progress bar while real scan runs
    intervalRef.current = setInterval(() => {
      p = Math.min(p + Math.random() * 1.5, 90);
      const phaseIdx = Math.min(Math.floor(p / 20), phases.length - 1);
      setPhase(phases[phaseIdx]);
      setProgress(Math.floor(p));
    }, 400);

    try {
      const res = await axios.post(`${API}/scan`, { target: target.trim(), scan_type: scanType });
      clearInterval(intervalRef.current);
      setProgress(100); setPhase("COMPLETE");
      const converted = convertRealResults(res.data.data);
      setVulns(converted);
    } catch (e) {
      clearInterval(intervalRef.current);
      setPhase("ERROR");
      setError(e.response?.data?.detail || "Scan failed. Check API server.");
    } finally {
      setScanning(false);
    }
  }

  function startSimScan() {
    if (scanning) return;
    setError(""); setScanning(true); setProgress(0); setVulns([]);
    let p = 0, phaseIdx = 0;
    intervalRef.current = setInterval(() => {
      p += Math.random() * 3 + 1;
      if (p >= 100) {
        p = 100; clearInterval(intervalRef.current);
        setScanning(false); setPhase("COMPLETE"); setVulns(VULN_TEMPLATES); return;
      }
      phaseIdx = Math.min(Math.floor(p / 20), phases.length - 1);
      setPhase(phases[phaseIdx]);
      setProgress(Math.floor(p));
      if (p > 40 && Math.random() < 0.1)
        setVulns(v => v.length < VULN_TEMPLATES.length ? [...v, VULN_TEMPLATES[v.length]] : v);
    }, 150);
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  vulns.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });

  return (
    <Panel>
      <SectionHeader icon="🔍" title="Vulnerability Scanner" color="#ff6b6b" />

      {/* Mode toggle */}
      <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
        {[
          { id: false, label: "SIMULATED" },
          { id: true,  label: "LIVE API"  },
        ].map(m => (
          <button key={String(m.id)} onClick={() => { setUseReal(m.id); setVulns([]); setPhase("IDLE"); setError(""); }}
            disabled={scanning}
            style={{
              background: useReal === m.id ? "rgba(0,255,136,0.15)" : "rgba(255,255,255,0.03)",
              border: `1px solid ${useReal === m.id ? "rgba(0,255,136,0.5)" : "rgba(255,255,255,0.08)"}`,
              color: useReal === m.id ? "#00ff88" : "#555",
              fontFamily: "'Share Tech Mono', monospace", fontSize: 9,
              padding: "4px 12px", borderRadius: 3, cursor: "pointer", letterSpacing: 1
            }}>{m.label}</button>
        ))}
        {useReal && (
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
            <PulsingDot color={apiOnline ? "#00ff88" : "#ff4444"} size={6} />
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: apiOnline ? "#00ff88" : "#ff4444" }}>
              {apiOnline ? "API LIVE" : "API DOWN"}
            </span>
          </div>
        )}
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: useReal ? 8 : 14, alignItems: "center" }}>
        <input value={target} onChange={e => setTarget(e.target.value)} disabled={scanning}
          style={{
            flex: 1, background: "rgba(255,107,107,0.08)", border: "1px solid rgba(255,107,107,0.3)",
            color: "#e0e0e0", fontFamily: "'Share Tech Mono', monospace", fontSize: 11,
            padding: "6px 10px", borderRadius: 4, outline: "none"
          }} placeholder="Target IP / CIDR" />
        <button onClick={useReal ? startRealScan : startSimScan}
          disabled={scanning || (useReal && !apiOnline)}
          style={{
            background: scanning ? "rgba(255,107,107,0.1)" : "rgba(255,107,107,0.2)",
            border: "1px solid rgba(255,107,107,0.5)", color: scanning ? "#888" : "#ff6b6b",
            fontFamily: "'Orbitron', sans-serif", fontSize: 9, fontWeight: 700,
            padding: "7px 14px", borderRadius: 4, cursor: scanning ? "not-allowed" : "pointer",
            letterSpacing: 1, transition: "all 0.2s"
          }}>{scanning ? "SCANNING..." : "RUN SCAN"}</button>
      </div>

      {useReal && (
        <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
          {["basic","version","full"].map(m => (
            <button key={m} onClick={() => setScanType(m)} disabled={scanning}
              style={{
                background: scanType === m ? "rgba(255,107,107,0.15)" : "rgba(255,255,255,0.03)",
                border: `1px solid ${scanType === m ? "rgba(255,107,107,0.4)" : "rgba(255,255,255,0.06)"}`,
                color: scanType === m ? "#ff6b6b" : "#444",
                fontFamily: "'Share Tech Mono', monospace", fontSize: 9,
                padding: "4px 10px", borderRadius: 3, cursor: "pointer", letterSpacing: 1,
                textTransform: "uppercase"
              }}>{m}</button>
          ))}
        </div>
      )}

      {error && (
        <div style={{ background: "rgba(255,45,45,0.1)", border: "1px solid rgba(255,45,45,0.3)", borderRadius: 4, padding: "7px 10px", color: "#ff6b6b", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, marginBottom: 10 }}>
          ⚠ {error}
        </div>
      )}

      {(scanning || phase === "COMPLETE") && <ScanProgress progress={progress} phase={phase} />}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 6, marginBottom: 14 }}>
        {Object.entries(counts).map(([sev, n]) => (
          <div key={sev} style={{ background: SEV[sev].bg, border: `1px solid ${SEV[sev].border}`, borderRadius: 5, padding: "8px 0", textAlign: "center" }}>
            <div style={{ fontFamily: "'Orbitron', sans-serif", fontSize: 16, fontWeight: 700, color: SEV[sev].text }}>{n}</div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: SEV[sev].text, opacity: 0.8, letterSpacing: 1 }}>{sev}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 5, maxHeight: 240, overflowY: "auto" }}>
        {vulns.length === 0 && !scanning && (
          <div style={{ color: "#444", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, textAlign: "center", padding: "20px 0" }}>
            — awaiting scan —
          </div>
        )}
        {vulns.map((v, i) => {
          const sev = v.severity in SEV ? v.severity : "LOW";
          const s = SEV[sev];
          return (
            <div key={i} style={{ background: s.bg, border: `1px solid ${s.border}33`, borderLeft: `3px solid ${s.border}`, borderRadius: 4, padding: "7px 10px", animation: "fadeIn 0.3s ease" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#e0e0e0", fontWeight: 700 }}>{v.name}</span>
                <Badge label={sev} sev={s} />
              </div>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#666" }}>{v.id}</span>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#67d9ff" }}>{v.host}:{v.port}</span>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#aaa" }}>{v.service}</span>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: s.text }}>CVSS {v.cvss}</span>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

// ── WiFi IDS (unchanged) ───────────────────────────────────────────────────
function WifiIDS() {
  const [monitoring, setMonitoring] = useState(false);
  const [alerts,     setAlerts]     = useState([]);
  const [packetCount,setPacketCount]= useState(0);
  const [apCount,    setApCount]    = useState(0);
  const [channel,    setChannel]    = useState(6);
  const intervalRef = useRef(null);

  useEffect(() => {
    if (monitoring) {
      intervalRef.current = setInterval(() => {
        setPacketCount(p => p + Math.floor(Math.random()*800+200));
        setApCount(Math.floor(Math.random()*4+12));
        setChannel([1,6,11,1,6,11,6][Math.floor(Math.random()*7)]);
        if (Math.random() < 0.25) setAlerts(a => [genWifiAlert(), ...a].slice(0, 30));
      }, 1200);
    } else clearInterval(intervalRef.current);
    return () => clearInterval(intervalRef.current);
  }, [monitoring]);

  return (
    <Panel>
      <SectionHeader icon="📡" title="WiFi Intrusion Detection" color="#67d9ff" />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 14 }}>
        {[
          { label: "PACKETS", val: packetCount.toLocaleString(), color: "#67d9ff" },
          { label: "APs SEEN", val: apCount, color: "#00ff88" },
          { label: "CHANNEL", val: `CH ${channel}`, color: "#ffe55c" },
        ].map(({ label, val, color }) => (
          <div key={label} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 5, padding: "10px 8px", textAlign: "center" }}>
            <div style={{ fontFamily: "'Orbitron', sans-serif", fontSize: 14, fontWeight: 700, color }}>{val}</div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#555", letterSpacing: 1, marginTop: 2 }}>{label}</div>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <PulsingDot color={monitoring ? "#00ff88" : "#444"} />
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: monitoring ? "#00ff88" : "#555" }}>
          {monitoring ? "MONITOR MODE ACTIVE — wlan0mon" : "INTERFACE INACTIVE"}
        </span>
        <button onClick={() => setMonitoring(m => !m)} style={{
          marginLeft: "auto",
          background: monitoring ? "rgba(255,107,107,0.15)" : "rgba(103,217,255,0.15)",
          border: `1px solid ${monitoring ? "rgba(255,107,107,0.4)" : "rgba(103,217,255,0.4)"}`,
          color: monitoring ? "#ff6b6b" : "#67d9ff",
          fontFamily: "'Orbitron', sans-serif", fontSize: 9, fontWeight: 700,
          padding: "6px 12px", borderRadius: 4, cursor: "pointer", letterSpacing: 1
        }}>{monitoring ? "STOP" : "START"}</button>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 5, maxHeight: 260, overflowY: "auto" }}>
        {alerts.length === 0 && <div style={{ color: "#444", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, textAlign: "center", padding: "20px 0" }}>— no alerts captured —</div>}
        {alerts.map(a => {
          const s = WIFI_SEV[a.type] || SEV.MEDIUM;
          return (
            <div key={a.id} style={{ background: s.bg, border: `1px solid ${s.border}33`, borderLeft: `3px solid ${s.border}`, borderRadius: 4, padding: "7px 10px", animation: "fadeIn 0.3s ease" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: s.text, fontWeight: 700 }}>{a.type.replace(/_/g, " ")}</span>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#555" }}>{a.ts.toLocaleTimeString()}</span>
              </div>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#aaa", marginBottom: 3 }}>{a.detail}</div>
              <div style={{ display: "flex", gap: 10 }}>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#67d9ff" }}>{a.device}</span>
                {a.ssid !== "—" && <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#ffe55c" }}>SSID: {a.ssid}</span>}
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#555" }}>CH{a.channel}</span>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

// ── CCTV Monitor (REAL API) ────────────────────────────────────────────────
function CctvMonitor() {
  const [cameras,    setCameras]    = useState([]);   // live cameras from API
  const [alerts,     setAlerts]     = useState([]);   // real alerts from API
  const [available,  setAvailable]  = useState([]);   // detected webcams
  const [active,     setActive]     = useState(false);
  const [loading,    setLoading]    = useState(false);
  const [snapshots,  setSnapshots]  = useState({});   // camera_id → img src
  const [stats,      setStats]      = useState(null);
  const intervalRef  = useRef(null);
  const snapInterval = useRef(null);

  const statusColor = { online: "#00ff88", degraded: "#ffd700", offline: "#ff4444" };

  // ── Fetch available webcams on mount ──────
  useEffect(() => {
    axios.get("/cctv/cameras/available")
      .then(r => setAvailable(r.data.cameras || []))
      .catch(() => {});
    fetchAlerts();
    fetchCameras();
  }, []);

  async function fetchCameras() {
    try {
      const r = await axios.get("/cctv/cameras");
      setCameras(r.data.cameras || []);
      setStats(r.data.stats);
    } catch {}
  }

  async function fetchAlerts() {
    try {
      const r = await axios.get("/cctv/alerts?limit=20");
      const live = r.data.live_alerts || [];
      const db   = r.data.db_alerts   || [];
      // Merge and deduplicate by id
      const merged = [...live, ...db].slice(0, 20);
      setAlerts(merged);
    } catch {}
  }

  // ── Fetch snapshots from all active cameras ──
  async function fetchSnapshots() {
  for (const cam of cameras) {
    if (cam.status !== "online" && cam.status !== "degraded") continue;
    try {
      const token = localStorage.getItem("safenet_token");
      const response = await fetch(
        `http://127.0.0.1:8000/cctv/cameras/${cam.camera_id}/snapshot?t=${Date.now()}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!response.ok) continue;
      const blob = await response.blob();
      const imgUrl = URL.createObjectURL(blob);
      setSnapshots(prev => {
        if (prev[cam.camera_id]) URL.revokeObjectURL(prev[cam.camera_id]);
        return { ...prev, [cam.camera_id]: imgUrl };
      });
    } catch (err) {
      console.error("Snapshot error:", err);
    }
  }
}

  // ── Start / Stop monitoring ───────────────
  async function startMonitoring() {
    if (available.length === 0) {
      alert("No cameras detected. Make sure Iriun is running.");
      return;
    }
    setLoading(true);
    try {
      // Add each detected camera
      for (let i = 0; i < available.length; i++) {
        const cam = available[i];
        await axios.post("/cctv/cameras", {
          camera_id:          `CAM-0${i + 1}`,
          source:             String(cam.index),
          name:               i === 0 ? "Iriun Phone Camera" : `Webcam ${i + 1}`,
          location:           i === 0 ? "Primary Monitor" : `Station ${i + 1}`,
          motion_sensitivity: 0.4,
        }).catch(() => {});  // ignore if already added
      }
      setActive(true);
      await fetchCameras();

      // Poll snapshots every 800ms
      snapInterval.current = setInterval(() => {
        fetchSnapshots();
        fetchAlerts();
        fetchCameras();
      }, 800);

    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  async function stopMonitoring() {
    setLoading(true);
    try {
      await axios.post("/cctv/stop-all");
      setActive(false);
      clearInterval(snapInterval.current);
      await fetchCameras();
    } catch {} finally { setLoading(false); }
  }

  // Cleanup on unmount
  useEffect(() => () => {
    clearInterval(snapInterval.current);
    Object.values(snapshots).forEach(URL.revokeObjectURL);
  }, []);

  return (
    <Panel style={{ gridColumn: "1 / -1" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <span style={{ fontSize: 18 }}>📹</span>
        <span style={{ fontFamily: "'Orbitron', sans-serif", fontSize: 12, color: "#ffe55c", letterSpacing: 2, fontWeight: 700 }}>
          CCTV NETWORK SECURITY
        </span>
        {stats && (
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#555" }}>
            {stats.online}/{stats.total_cameras} online · {stats.total_alerts} alerts
          </span>
        )}
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          {available.length > 0 && (
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#00ff88" }}>
              {available.length} camera{available.length > 1 ? "s" : ""} detected
            </span>
          )}
          <button onClick={active ? stopMonitoring : startMonitoring} disabled={loading}
            style={{
              background: active ? "rgba(255,107,107,0.15)" : "rgba(255,229,92,0.15)",
              border: `1px solid ${active ? "rgba(255,107,107,0.4)" : "rgba(255,229,92,0.4)"}`,
              color: active ? "#ff6b6b" : "#ffe55c",
              fontFamily: "'Orbitron', sans-serif", fontSize: 9, fontWeight: 700,
              padding: "6px 12px", borderRadius: 4, cursor: loading ? "not-allowed" : "pointer", letterSpacing: 1
            }}>{loading ? "..." : active ? "STOP MONITOR" : "START MONITOR"}</button>
        </div>
      </div>

      {/* Camera grid */}
      {cameras.length === 0 ? (
        <div style={{
          padding: "24px", textAlign: "center", border: "1px dashed rgba(255,229,92,0.2)",
          borderRadius: 6, marginBottom: 14, color: "#555",
          fontFamily: "'Share Tech Mono', monospace", fontSize: 11
        }}>
          {available.length > 0
            ? `${available.length} camera(s) ready — click START MONITOR to begin`
            : "No cameras detected — connect Iriun via USB and click START MONITOR"}
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: `repeat(${Math.min(cameras.length, 4)}, 1fr)`, gap: 8, marginBottom: 16 }}>
          {cameras.map(cam => (
            <div key={cam.camera_id} style={{
              border: `1px solid ${(statusColor[cam.status] || "#555")}44`,
              borderRadius: 6, overflow: "hidden", background: "#040810"
            }}>
              {/* Live snapshot */}
              {snapshots[cam.camera_id] ? (
                <img
                  src={snapshots[cam.camera_id]}
                  alt={cam.name}
                  key={snapshots[cam.camera_id]}
                  style={{ width: "100%", height: 90, objectFit: "cover", display: "block" }}
                />
              ) : (
                <div style={{
                  width: "100%", height: 90, background: "#0a0f18",
                  display: "flex", alignItems: "center", justifyContent: "center"
                }}>
                  <span style={{ fontSize: 20, opacity: 0.3 }}>📷</span>
                </div>
              )}
              {/* Camera info */}
              <div style={{ padding: "6px 8px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 2 }}>
                  <PulsingDot color={statusColor[cam.status] || "#555"} size={5} />
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#aaa", fontWeight: 700 }}>{cam.camera_id}</span>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 7, color: "#444", marginLeft: "auto" }}>
                    {cam.fps > 0 ? `${cam.fps}fps` : "—"}
                  </span>
                </div>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 7, color: "#555" }}>{cam.name}</div>
                <div style={{ display: "flex", justifyContent: "space-between", marginTop: 2 }}>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 7, color: statusColor[cam.status] || "#555" }}>
                    {(cam.status || "offline").toUpperCase()}
                  </span>
                  {cam.motion_events > 0 && (
                    <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 7, color: "#ff6b6b" }}>
                      {cam.motion_events} motion
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Security events */}
      <div>
        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#555", marginBottom: 8, letterSpacing: 1 }}>
          ▸ SECURITY EVENTS {alerts.length > 0 && `(${alerts.length})`}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 5, maxHeight: 160, overflowY: "auto" }}>
          {alerts.length === 0 && (
            <div style={{ color: "#444", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, textAlign: "center", padding: "12px 0" }}>
              — no events logged —
            </div>
          )}
          {alerts.map((a, i) => {
            const sevKey = a.severity in SEV ? a.severity : "MEDIUM";
            const s = SEV[sevKey];
            const ts = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : "—";
            return (
              <div key={a.id || i} style={{
                background: s.bg, border: `1px solid ${s.border}33`,
                borderLeft: `3px solid ${s.border}`, borderRadius: 4,
                padding: "6px 10px", display: "flex", alignItems: "center",
                gap: 10, animation: "fadeIn 0.3s ease", flexWrap: "wrap"
              }}>
                <Badge label={a.camera_id || a.cam || "—"} sev={{ bg: "transparent", border: "#555", text: "#aaa" }} />
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: s.text, fontWeight: 700, minWidth: 120 }}>
                  {(a.type || "EVENT").replace(/_/g, " ")}
                </span>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#888", flex: 1 }}>{a.detail}</span>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#444" }}>{ts}</span>
              </div>
            );
          })}
        </div>
      </div>
    </Panel>
  );
}

// ── Threat Timeline (unchanged) ────────────────────────────────────────────
function ThreatTimeline({ events }) {
  return (
    <Panel style={{ gridColumn: "1 / -1" }}>
      <SectionHeader icon="⚡" title="Live Threat Feed" color="#00ff88" count={events.length} />
      <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 120, overflowY: "auto" }}>
        {events.length === 0 && <div style={{ color: "#444", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, textAlign: "center", padding: "16px 0" }}>— system nominal —</div>}
        {events.map((e, i) => (
          <div key={i} style={{ display: "flex", gap: 12, alignItems: "center", padding: "4px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#444", minWidth: 65 }}>{e.ts}</span>
            <Badge label={e.source} sev={{ bg: "rgba(0,255,136,0.1)", border: "#00ff88", text: "#00ff88" }} />
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#aaa" }}>{e.msg}</span>
            <Badge label={e.sev} sev={SEV[e.sev] || SEV.MEDIUM} />
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── MAIN APP ───────────────────────────────────────────────────────────────
export default function App() {
  const [authUser, setAuthUser] = useState(() => {
    const s = localStorage.getItem("safenet_user");
    return s ? JSON.parse(s) : null;
  });

  function handleLogin(data) {
    setAuthUser({ username: data.username, full_name: data.full_name, role: data.role });
  }

  function handleLogout() {
    localStorage.removeItem("safenet_token");
    localStorage.removeItem("safenet_user");
    setAuthUser(null);
  }

  // Show login if not authenticated
  if (!authUser) return <Login onLogin={handleLogin} />;

  return <Dashboard authUser={authUser} onLogout={handleLogout} />;
}

function Dashboard({ authUser, onLogout }) {
  const [events,      setEvents]      = useState([]);
  const [uptime,      setUptime]      = useState(0);
  const [threatLevel, setThreatLevel] = useState("NOMINAL");

  useEffect(() => {
    const t = setInterval(() => setUptime(u => u + 1), 1000);
    const e = setInterval(() => {
      const sources = [
        { source: "VULN", msgs: ["New CVE matched on 192.168.1.10", "Port scan completed", "CVSS 9.8 finding logged"], sev: "CRITICAL" },
        { source: "WIFI", msgs: ["Deauth flood on CH6", "PMKID capture attempt", "Rogue AP detected"], sev: "HIGH" },
        { source: "CCTV", msgs: ["Motion in restricted area", "Stream anomaly detected", "Auth failure on VMS"], sev: "HIGH" },
        { source: "SYS",  msgs: ["Config backup completed", "Signature DB updated", "Health check passed"], sev: "LOW" },
      ];
      const s = rand(sources);
      const msg = rand(s.msgs);
      const now = new Date();
      setEvents(ev => [{ ts: now.toLocaleTimeString(), source: s.source, msg, sev: s.sev }, ...ev].slice(0, 50));
      setThreatLevel(() => {
        const t = Math.random();
        if (t < 0.1) return "CRITICAL";
        if (t < 0.3) return "ELEVATED";
        if (t < 0.6) return "GUARDED";
        return "NOMINAL";
      });
    }, 2500);
    return () => { clearInterval(t); clearInterval(e); };
  }, []);

  const fmt = (s) => `${String(Math.floor(s/3600)).padStart(2,"0")}:${String(Math.floor((s%3600)/60)).padStart(2,"0")}:${String(s%60).padStart(2,"0")}`;
  const tlColor = { NOMINAL: "#00ff88", GUARDED: "#ffe55c", ELEVATED: "#ff8c00", CRITICAL: "#ff2d2d" };

  return (
    <div style={{
      minHeight: "100vh", background: "#040810",
      backgroundImage: `
        radial-gradient(ellipse 60% 40% at 20% 20%, rgba(0,255,136,0.04) 0%, transparent 60%),
        radial-gradient(ellipse 50% 50% at 80% 80%, rgba(103,217,255,0.03) 0%, transparent 60%),
        repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0,255,136,0.015) 39px, rgba(0,255,136,0.015) 40px),
        repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,255,136,0.015) 39px, rgba(0,255,136,0.015) 40px)
      `,
      padding: "0 0 40px 0", fontFamily: "'Share Tech Mono', monospace"
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(0,255,136,0.2); border-radius: 2px; }
        @keyframes ping { 0%{transform:scale(1);opacity:.5} 75%,100%{transform:scale(2.2);opacity:0} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:translateY(0)} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes loginIn { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
        @keyframes hexSpin { 0%,100%{filter:drop-shadow(0 0 8px #00ff8844)} 50%{filter:drop-shadow(0 0 20px #00ff88aa)} }
        @keyframes errShake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-6px)} 75%{transform:translateX(6px)} }
      `}</style>

      {/* Header */}
      <div style={{
        borderBottom: "1px solid rgba(0,255,136,0.15)",
        padding: "14px 24px", display: "flex", alignItems: "center", gap: 20,
        background: "rgba(4,8,16,0.9)", backdropFilter: "blur(10px)",
        position: "sticky", top: 0, zIndex: 100
      }}>
        <div>
          <div style={{ fontFamily: "'Orbitron', sans-serif", fontWeight: 900, fontSize: 16, color: "#00ff88", letterSpacing: 3 }}>SENTINEL</div>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#335", letterSpacing: 2 }}>INTEGRATED SECURITY OPERATIONS CENTRE</div>
        </div>

        <div style={{ marginLeft: "auto", display: "flex", gap: 24, alignItems: "center" }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontFamily: "'Orbitron', sans-serif", fontSize: 13, fontWeight: 700, color: tlColor[threatLevel], animation: threatLevel === "CRITICAL" ? "blink 0.8s infinite" : "none" }}>
              {threatLevel}
            </div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#444", letterSpacing: 1 }}>THREAT LEVEL</div>
          </div>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontFamily: "'Orbitron', sans-serif", fontSize: 13, fontWeight: 700, color: "#67d9ff" }}>{fmt(uptime)}</div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#444", letterSpacing: 1 }}>UPTIME</div>
          </div>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontFamily: "'Orbitron', sans-serif", fontSize: 13, fontWeight: 700, color: "#00ff88" }}>
              {events.filter(e => e.sev === "CRITICAL").length}
            </div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#444", letterSpacing: 1 }}>CRITICAL</div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <PulsingDot color="#00ff88" size={7} />
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#00ff88" }}>LIVE</span>
          </div>

          {/* User + Logout */}
          <div style={{ borderLeft: "1px solid rgba(0,255,136,0.15)", paddingLeft: 20, display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#e0e0e0" }}>{authUser.full_name}</div>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: authUser.role === "admin" ? "#ff6b6b" : "#67d9ff", letterSpacing: 1 }}>
                {authUser.role.toUpperCase()}
              </div>
            </div>
            <button onClick={onLogout} style={{
              background: "rgba(255,45,45,0.1)", border: "1px solid rgba(255,45,45,0.3)",
              color: "#ff6b6b", fontFamily: "'Share Tech Mono', monospace", fontSize: 9,
              padding: "5px 12px", borderRadius: 4, cursor: "pointer", letterSpacing: 1,
              transition: "all 0.2s"
            }}>LOGOUT</button>
          </div>
        </div>
      </div>

      {/* Module Status Bar */}
      <div style={{
        margin: "0 24px", padding: "10px 16px",
        background: "rgba(10,18,30,0.85)", border: "1px solid rgba(0,255,136,0.15)",
        borderRadius: 8, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center"
      }}>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#335", letterSpacing: 2, marginRight: 6 }}>// MODULES</span>
        {[
          { name: "Vuln Scanner",  status: "LIVE",     color: "#00ff88" },
          { name: "JWT Auth",      status: "LIVE",     color: "#00ff88" },
          { name: "PostgreSQL",    status: "LIVE",     color: "#00ff88" },
          { name: "React Dashboard",status:"LIVE",     color: "#00ff88" },
          { name: "WiFi IDS",      status: "LIVE",     color: "#00ff88" },
          { name: "CCTV Monitor",  status: "LIVE",    color: "#00ff88" },
          { name: "Flutter App",   status: "PLANNED", color: "#555"    },
        ].map(m => (
          <span key={m.name} style={{
            fontFamily: "'Share Tech Mono', monospace", fontSize: 8,
            color: m.color, background: m.color + "12",
            border: `1px solid ${m.color}30`, padding: "2px 8px", borderRadius: 2,
            letterSpacing: 1
          }}>
            {m.status === "LIVE" ? "●" : m.status === "BUILDING" ? "◌" : "○"} {m.name}
          </span>
        ))}
        <span style={{ marginLeft: "auto", fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#335" }}>v0.5.0</span>
      </div>

      {/* Main Grid */}
      <div style={{ padding: "16px 24px 20px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <ThreatTimeline events={events.slice(0, 12)} />
        <VulnScanner authUser={authUser} />
        <WifiIDS />
        <CctvMonitor />
      </div>
    </div>
  );
}
