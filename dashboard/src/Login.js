import { useState, useEffect, useRef } from "react";
import axios from "axios";
import "./Login.css";

const API = "http://127.0.0.1:8000";

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
          hex(x, y, r - 2, w * 0.06 + 0.015);
        }
      }
      id = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(id); window.removeEventListener("resize", resize); };
  }, []);
  return <canvas ref={ref} className="login-canvas" />;
}

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [showPass, setShowPass] = useState(false);
  const [dots,     setDots]     = useState(0);

  useEffect(() => {
    if (!loading) return;
    const id = setInterval(() => setDots(d => (d + 1) % 4), 400);
    return () => clearInterval(id);
  }, [loading]);

  async function handleLogin(e) {
    e.preventDefault();
    if (!username || !password) { setError("Enter username and password."); return; }
    setError(""); setLoading(true);

    try {
      // FastAPI OAuth2 expects form data, not JSON
      const form = new FormData();
      form.append("username", username);
      form.append("password", password);

      const res = await axios.post(`${API}/auth/login`, form, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });

      // Store token in localStorage
      localStorage.setItem("safenet_token",     res.data.access_token);
      localStorage.setItem("safenet_user",      JSON.stringify({
        username:  res.data.username,
        full_name: res.data.full_name,
        role:      res.data.role,
      }));

      onLogin(res.data);
    } catch (e) {
      setError(e.response?.data?.detail || "Login failed. Check your credentials.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-wrap">
      <HexCanvas />

      <div className="login-box">
        {/* Logo */}
        <div className="login-logo">
          <div className="login-hex">⬡</div>
          <div>
            <div className="login-name">SafeNet</div>
            <div className="login-country">GHANA</div>
          </div>
        </div>

        <div className="login-tagline">
          Integrated Security System<br />
          <span>GCTU Cybersecurity · Patrick Idan</span>
        </div>

        {/* Form */}
        <form className="login-form" onSubmit={handleLogin}>
          <div className="lf-group">
            <label className="lf-label">USERNAME</label>
            <div className="lf-inp-wrap">
              <span className="lf-icon">◈</span>
              <input
                className="lf-inp"
                type="text"
                placeholder="admin"
                value={username}
                onChange={e => setUsername(e.target.value)}
                disabled={loading}
                autoComplete="username"
              />
            </div>
          </div>

          <div className="lf-group">
            <label className="lf-label">PASSWORD</label>
            <div className="lf-inp-wrap">
              <span className="lf-icon">▦</span>
              <input
                className="lf-inp"
                type={showPass ? "text" : "password"}
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                disabled={loading}
                autoComplete="current-password"
              />
              <button
                type="button"
                className="lf-toggle"
                onClick={() => setShowPass(s => !s)}>
                {showPass ? "hide" : "show"}
              </button>
            </div>
          </div>

          {error && (
            <div className="lf-error">
              <span>⚠</span> {error}
            </div>
          )}

          <button className={`lf-btn ${loading ? "lf-busy" : ""}`} type="submit" disabled={loading}>
            {loading
              ? `AUTHENTICATING${".".repeat(dots)}`
              : "▶  ACCESS SYSTEM"}
          </button>
        </form>

        {/* Demo credentials hint */}
        <div className="login-hint">
          <div className="hint-title">// DEMO CREDENTIALS</div>
          <div className="hint-row">
            <span className="hint-role admin">ADMIN</span>
            <span className="hint-cred">admin / admin123</span>
          </div>
          <div className="hint-row">
            <span className="hint-role viewer">VIEWER</span>
            <span className="hint-cred">viewer / viewer123</span>
          </div>
        </div>

        <div className="login-footer">
          SafeNet Ghana v0.2.0 · Final Year Project · GCTU
        </div>
      </div>
    </div>
  );
}
