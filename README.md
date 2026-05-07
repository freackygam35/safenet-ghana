# SafeNet Ghana 🇬🇭

> Affordable, all-in-one network security system for small businesses in Ghana.

Built by **Patrick Idan** | GCTU Cybersecurity Evening Programme | Final Year Project

---

## What is SafeNet Ghana?

Most small businesses in Ghana cannot afford enterprise security tools like Nessus or Cisco Umbrella. SafeNet Ghana is an open-source, integrated security system that brings professional-grade protection to any small business network — accessible from both PC and mobile.

---

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| Vulnerability Scanner | ✅ Live | Scans networks for open ports and known vulnerabilities |
| WiFi Intrusion Detection | 🔨 Building | Detects rogue APs, deauth attacks, ARP spoofing |
| CCTV Network Monitor | 🔨 Building | Monitors IP camera traffic for unauthorized access |

---

## Tech Stack

- **Backend** — Python + FastAPI
- **Scanner Engine** — nmap + python-nmap
- **Database** — PostgreSQL (coming)
- **Web Dashboard** — React.js (coming)
- **Mobile App** — Flutter (coming)
- **Deployment** — Docker + DigitalOcean (coming)

---

## Getting Started

### Requirements
- Python 3.10+
- nmap installed and in PATH → [nmap.org](https://nmap.org/download.html)

### Install dependencies
```bash
cd scanner
pip install -r requirements.txt
```

### Run the scanner (CLI)
```bash
python scanner.py
```

### Run the API server
```bash
python -m uvicorn api:app --reload --host 127.0.0.1 --port 8000
```

### View API docs
Open your browser at: `http://127.0.0.1:8000/docs`

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | System info |
| GET | `/health` | Health check |
| POST | `/scan` | Trigger a vulnerability scan |
| GET | `/scans/history` | All past scans |
| GET | `/scans/latest` | Most recent scan |
| GET | `/scans/stats` | Dashboard statistics |

### Example scan request
```json
POST /scan
{
  "target": "192.168.1.1",
  "scan_type": "basic"
}
```

---

## Project Roadmap

- [x] Vulnerability scanner core engine
- [x] FastAPI backend with REST endpoints
- [x] JSON scan reports
- [ ] PostgreSQL database integration
- [ ] React.js web dashboard
- [ ] WiFi intrusion detection module
- [ ] CCTV network monitor module
- [ ] Flutter mobile app
- [ ] Docker deployment
- [ ] Google Play Store release

---

## License

MIT License — free to use, modify, and distribute.

---

*SafeNet Ghana — Security for every business, not just the big ones.*
