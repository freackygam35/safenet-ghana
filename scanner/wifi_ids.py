"""
SafeNet Ghana - WiFi Intrusion Detection System (Module 2)
Detects real WiFi attacks using Scapy packet analysis.

Detects:
  - Deauthentication Flood
  - Evil Twin / Rogue AP
  - ARP Spoofing (MitM)
  - MAC Spoofing
  - PMKID Harvesting
  - WPS Brute Force
  - Probe Sweep (Reconnaissance)
  - Eavesdropping (Unencrypted Traffic)
  - Beacon Flood

Author: Patrick Idan
Project: SafeNet Ghana - GCTU Cybersecurity
"""

import threading
import time
import json
import datetime
from collections import defaultdict
from typing import Callable, Optional

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
        Dot11Deauth, Dot11Disassoc, Dot11AssoReq, Dot11Auth,
        ARP, Ether, conf, get_if_list, RadioTap, Dot11Elt,
        EAPOL
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WIFI] Scapy not available — running in simulation mode")

# ─────────────────────────────────────────────
#  SEVERITY MAP
# ─────────────────────────────────────────────
ATTACK_SEVERITY = {
    "DEAUTH_FLOOD":    "CRITICAL",
    "EVIL_TWIN":       "CRITICAL",
    "MITM_ARP_SPOOF":  "CRITICAL",
    "PMKID_HARVEST":   "CRITICAL",
    "ROGUE_AP":        "HIGH",
    "MAC_SPOOF":       "HIGH",
    "WPS_BRUTE":       "HIGH",
    "EAVESDROPPING":   "HIGH",
    "PROBE_SWEEP":     "MEDIUM",
    "BEACON_FLOOD":    "MEDIUM",
    "DISASSOC_FLOOD":  "HIGH",
}

ATTACK_DESCRIPTIONS = {
    "DEAUTH_FLOOD":   "Deauthentication flood — attacker forcing clients off network",
    "EVIL_TWIN":      "Evil Twin AP detected — fake network cloning legitimate SSID",
    "MITM_ARP_SPOOF": "ARP spoofing detected — Man-in-the-Middle attack in progress",
    "PMKID_HARVEST":  "PMKID capture attempt — offline WPA2 password crack prep",
    "ROGUE_AP":       "Unauthorized access point detected on network",
    "MAC_SPOOF":      "MAC address spoofing — device impersonating trusted client",
    "WPS_BRUTE":      "WPS PIN brute force in progress — router PIN under attack",
    "EAVESDROPPING":  "Unencrypted traffic detected — passive eavesdropping possible",
    "PROBE_SWEEP":    "Passive probe sweep — device scanning all channels",
    "BEACON_FLOOD":   "Beacon flood attack — network disruption attempt",
    "DISASSOC_FLOOD": "Disassociation flood — clients being forcibly disconnected",
}


# ─────────────────────────────────────────────
#  WIFI IDS ENGINE
# ─────────────────────────────────────────────
class WiFiIDS:
    def __init__(self, alert_callback: Optional[Callable] = None):
        """
        alert_callback: function called when an attack is detected.
        Receives a dict with attack details.
        """
        self.alert_callback  = alert_callback
        self.running         = False
        self.sniff_thread    = None
        self.alerts          = []

        # ── Detection state trackers ──────────
        self.deauth_counts   = defaultdict(list)   # MAC → [timestamps]
        self.beacon_counts   = defaultdict(list)   # SSID → [timestamps]
        self.probe_counts    = defaultdict(list)   # MAC → [timestamps]
        self.arp_table       = {}                  # IP → MAC
        self.known_aps       = {}                  # BSSID → SSID
        self.wps_counts      = defaultdict(list)   # MAC → [timestamps]
        self.seen_macs       = set()
        self.eapol_counts    = defaultdict(list)   # MAC → [timestamps]

        # ── Thresholds ────────────────────────
        self.DEAUTH_THRESHOLD   = 5    # deauths in 10 seconds = flood
        self.BEACON_THRESHOLD   = 50   # beacons in 5 seconds = flood
        self.PROBE_THRESHOLD    = 20   # probes in 10 seconds = sweep
        self.WPS_THRESHOLD      = 10   # WPS auths in 30 seconds = brute
        self.EAPOL_THRESHOLD    = 8    # EAPOLs in 10 seconds = PMKID

        # ── Whitelisted SSIDs (legitimate APs) ─
        # Add your real network SSIDs here
        self.whitelist_ssids = set()
        self.whitelist_bssids = set()

        # ── Interface ─────────────────────────
        self.interface = None
        self.packets_seen = 0
        self.start_time   = None

    def add_to_whitelist(self, ssid: str = None, bssid: str = None):
        """Add a known legitimate AP to the whitelist."""
        if ssid:  self.whitelist_ssids.add(ssid)
        if bssid: self.whitelist_bssids.add(bssid.upper())

    def _fire_alert(self, attack_type: str, device_mac: str,
                    ssid: str = None, channel: int = None,
                    detail: str = None, extra: dict = None):
        """Creates and dispatches an alert."""
        alert = {
            "id":          f"{attack_type[:4]}-{int(time.time()*1000) % 999999:06d}",
            "type":        attack_type,
            "severity":    ATTACK_SEVERITY.get(attack_type, "MEDIUM"),
            "device_mac":  device_mac or "Unknown",
            "ssid":        ssid or "—",
            "channel":     channel,
            "detail":      detail or ATTACK_DESCRIPTIONS.get(attack_type, ""),
            "description": ATTACK_DESCRIPTIONS.get(attack_type, ""),
            "timestamp":   datetime.datetime.now().isoformat(),
            "extra":       extra or {},
        }

        self.alerts.append(alert)
        # Keep last 500 alerts
        if len(self.alerts) > 500:
            self.alerts = self.alerts[-500:]

        print(f"[WIFI ALERT] {alert['severity']:8s} | {attack_type:20s} | {device_mac} | {alert['detail'][:50]}")

        if self.alert_callback:
            self.alert_callback(alert)

    def _clean_old(self, tracker: dict, window: int):
        """Remove timestamps older than window seconds."""
        now = time.time()
        for key in list(tracker.keys()):
            tracker[key] = [t for t in tracker[key] if now - t < window]
            if not tracker[key]:
                del tracker[key]

    # ── PACKET HANDLERS ──────────────────────

    def _handle_deauth(self, pkt):
        """Detect deauthentication/disassociation floods."""
        src = pkt[Dot11].addr2 or "FF:FF:FF:FF:FF:FF"
        dst = pkt[Dot11].addr1 or "FF:FF:FF:FF:FF:FF"

        now = time.time()
        self.deauth_counts[src].append(now)
        self._clean_old(self.deauth_counts, 10)

        if len(self.deauth_counts.get(src, [])) >= self.DEAUTH_THRESHOLD:
            attack = "DEAUTH_FLOOD" if pkt.haslayer(Dot11Deauth) else "DISASSOC_FLOOD"
            self._fire_alert(
                attack_type = attack,
                device_mac  = src,
                detail      = f"{attack.replace('_',' ')} from {src} targeting {dst} — {len(self.deauth_counts[src])} frames in 10s",
            )
            self.deauth_counts[src] = []  # reset after alert

    def _handle_beacon(self, pkt):
        """Detect Evil Twin and Rogue APs via beacon frames."""
        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt[Dot11].addr3 or pkt[Dot11].addr2
        if not bssid:
            return

        # Extract SSID from beacon
        ssid = ""
        try:
            ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore")
        except Exception:
            pass

        channel = None
        try:
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 3:
                    channel = int.from_bytes(elt.info, "big")
                    break
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass

        # Check encryption (eavesdropping risk)
        cap = pkt[Dot11Beacon].cap
        privacy = cap & 0x0010
        if not privacy and ssid and ssid not in self.whitelist_ssids:
            self._fire_alert(
                attack_type = "EAVESDROPPING",
                device_mac  = bssid,
                ssid        = ssid,
                channel     = channel,
                detail      = f"Open (unencrypted) network '{ssid}' — traffic visible to passive sniffers",
            )

        bssid_upper = bssid.upper()

        # Evil Twin detection — same SSID, different BSSID
        if ssid and ssid in self.whitelist_ssids and bssid_upper not in self.whitelist_bssids:
            self._fire_alert(
                attack_type = "EVIL_TWIN",
                device_mac  = bssid,
                ssid        = ssid,
                channel     = channel,
                detail      = f"Evil Twin: '{ssid}' seen from unauthorized BSSID {bssid} — cloning legitimate AP",
                extra       = {"known_ssid": ssid, "fake_bssid": bssid},
            )

        # Rogue AP detection — unknown BSSID broadcasting
        elif bssid_upper not in self.known_aps and bssid_upper not in self.whitelist_bssids:
            if ssid:  # only flag if it has an SSID
                self._fire_alert(
                    attack_type = "ROGUE_AP",
                    device_mac  = bssid,
                    ssid        = ssid,
                    channel     = channel,
                    detail      = f"Unknown AP '{ssid}' ({bssid}) — not in whitelist",
                )

        # Track seen APs
        self.known_aps[bssid_upper] = ssid

        # Beacon flood detection
        now = time.time()
        self.beacon_counts[ssid].append(now)
        self._clean_old(self.beacon_counts, 5)
        if len(self.beacon_counts.get(ssid, [])) >= self.BEACON_THRESHOLD:
            self._fire_alert(
                attack_type = "BEACON_FLOOD",
                device_mac  = bssid,
                ssid        = ssid,
                channel     = channel,
                detail      = f"Beacon flood on '{ssid}' — {len(self.beacon_counts[ssid])} beacons in 5s",
            )
            self.beacon_counts[ssid] = []

    def _handle_probe(self, pkt):
        """Detect probe request sweeps (reconnaissance)."""
        if not pkt.haslayer(Dot11ProbeReq):
            return

        src = pkt[Dot11].addr2
        if not src:
            return

        now = time.time()
        self.probe_counts[src].append(now)
        self._clean_old(self.probe_counts, 10)

        if len(self.probe_counts.get(src, [])) >= self.PROBE_THRESHOLD:
            self._fire_alert(
                attack_type = "PROBE_SWEEP",
                device_mac  = src,
                detail      = f"Probe sweep from {src} — {len(self.probe_counts[src])} probes in 10s — active reconnaissance",
            )
            self.probe_counts[src] = []

    def _handle_arp(self, pkt):
        """Detect ARP spoofing / MitM attacks."""
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        if arp.op != 2:  # ARP reply only
            return

        src_ip  = arp.psrc
        src_mac = arp.hwsrc.upper()

        if src_ip in self.arp_table:
            known_mac = self.arp_table[src_ip]
            if known_mac != src_mac:
                self._fire_alert(
                    attack_type = "MITM_ARP_SPOOF",
                    device_mac  = src_mac,
                    detail      = f"ARP spoofing: {src_ip} was {known_mac} now claiming {src_mac} — MitM in progress",
                    extra       = {
                        "target_ip":   src_ip,
                        "real_mac":    known_mac,
                        "spoof_mac":   src_mac,
                    }
                )
        else:
            self.arp_table[src_ip] = src_mac

    def _handle_eapol(self, pkt):
        """Detect PMKID harvesting and WPS brute force."""
        if not pkt.haslayer(EAPOL):
            return

        src = pkt[Dot11].addr2 if pkt.haslayer(Dot11) else None
        if not src:
            return

        now = time.time()
        self.eapol_counts[src].append(now)
        self._clean_old(self.eapol_counts, 10)

        if len(self.eapol_counts.get(src, [])) >= self.EAPOL_THRESHOLD:
            self._fire_alert(
                attack_type = "PMKID_HARVEST",
                device_mac  = src,
                detail      = f"PMKID harvest from {src} — {len(self.eapol_counts[src])} EAPOL frames in 10s — offline crack prep",
            )
            self.eapol_counts[src] = []

    def _handle_auth(self, pkt):
        """Detect WPS brute force via rapid auth attempts."""
        if not pkt.haslayer(Dot11Auth):
            return

        src = pkt[Dot11].addr2
        if not src:
            return

        now = time.time()
        self.wps_counts[src].append(now)
        self._clean_old(self.wps_counts, 30)

        if len(self.wps_counts.get(src, [])) >= self.WPS_THRESHOLD:
            self._fire_alert(
                attack_type = "WPS_BRUTE",
                device_mac  = src,
                detail      = f"WPS brute force from {src} — {len(self.wps_counts[src])} auth attempts in 30s",
            )
            self.wps_counts[src] = []

    def _handle_mac_spoof(self, pkt):
        """Detect MAC spoofing — locally administered MAC addresses."""
        if not pkt.haslayer(Dot11):
            return

        src = pkt[Dot11].addr2
        if not src or src == "ff:ff:ff:ff:ff:ff":
            return

        # Locally administered bit check
        try:
            first_byte = int(src.split(":")[0], 16)
            is_local   = bool(first_byte & 0x02)
            is_multicast = bool(first_byte & 0x01)

            if is_local and not is_multicast:
                if src not in self.seen_macs:
                    self.seen_macs.add(src)
                    self._fire_alert(
                        attack_type = "MAC_SPOOF",
                        device_mac  = src,
                        detail      = f"Locally administered MAC {src} — possible MAC spoofing/randomization",
                    )
        except Exception:
            pass

    # ── MAIN PACKET PROCESSOR ─────────────────
    def _process_packet(self, pkt):
        """Routes each packet to the right handler."""
        self.packets_seen += 1

        try:
            # Deauth / Disassoc
            if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disassoc):
                self._handle_deauth(pkt)

            # Beacon frames
            if pkt.haslayer(Dot11Beacon):
                self._handle_beacon(pkt)

            # Probe requests
            if pkt.haslayer(Dot11ProbeReq):
                self._handle_probe(pkt)

            # ARP (works on Ethernet too)
            if pkt.haslayer(ARP):
                self._handle_arp(pkt)

            # EAPOL (WPA2 handshake / PMKID)
            if pkt.haslayer(EAPOL):
                self._handle_eapol(pkt)

            # Auth frames (WPS brute)
            if pkt.haslayer(Dot11Auth):
                self._handle_auth(pkt)

            # MAC spoofing check
            if pkt.haslayer(Dot11):
                self._handle_mac_spoof(pkt)

        except Exception as e:
            pass  # Never crash on a single bad packet

    # ── START / STOP ──────────────────────────
    def start(self, interface: str = None):
        """Start the WiFi IDS on the given interface."""
        if self.running:
            return {"status": "already_running"}

        if not SCAPY_AVAILABLE:
            return {"status": "error", "detail": "Scapy not installed"}

        self.interface  = interface
        self.running    = True
        self.start_time = datetime.datetime.now()
        self.packets_seen = 0

        self.sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True
        )
        self.sniff_thread.start()

        print(f"[WIFI IDS] Started on interface: {interface or 'default'}")
        return {"status": "started", "interface": interface}

    def _sniff_loop(self):
        """Background thread that continuously sniffs packets."""
        try:
            if self.interface:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda p: not self.running,
                )
            else:
                # Sniff on all interfaces including ARP
                sniff(
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda p: not self.running,
                )
        except Exception as e:
            print(f"[WIFI IDS] Sniff error: {e}")
            self.running = False

    def stop(self):
        """Stop the WiFi IDS."""
        self.running = False
        print("[WIFI IDS] Stopped")
        return {"status": "stopped", "packets_seen": self.packets_seen, "alerts": len(self.alerts)}

    def get_status(self) -> dict:
        """Returns current IDS status."""
        uptime = None
        if self.start_time and self.running:
            uptime = int((datetime.datetime.now() - self.start_time).total_seconds())

        return {
            "running":      self.running,
            "interface":    self.interface,
            "packets_seen": self.packets_seen,
            "alerts_total": len(self.alerts),
            "uptime_secs":  uptime,
            "scapy_available": SCAPY_AVAILABLE,
        }

    def get_alerts(self, limit: int = 50, severity: str = None) -> list:
        """Returns recent alerts, newest first."""
        alerts = list(reversed(self.alerts))
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        return alerts[:limit]

    def get_stats(self) -> dict:
        """Returns alert breakdown by type and severity."""
        counts_by_type = defaultdict(int)
        counts_by_sev  = defaultdict(int)

        for a in self.alerts:
            counts_by_type[a["type"]] += 1
            counts_by_sev[a["severity"]] += 1

        return {
            "total_alerts":  len(self.alerts),
            "by_type":       dict(counts_by_type),
            "by_severity":   dict(counts_by_sev),
            "packets_seen":  self.packets_seen,
        }

    @staticmethod
    def list_interfaces() -> list:
        """Returns available network interfaces."""
        try:
            return get_if_list()
        except Exception:
            return []


# ─────────────────────────────────────────────
#  GLOBAL IDS INSTANCE
#  Shared across all API requests.
# ─────────────────────────────────────────────
wifi_ids = WiFiIDS()


# ─────────────────────────────────────────────
#  STANDALONE TEST
#  Run directly: python wifi_ids.py
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("""
  ╔══════════════════════════════════════╗
  ║   SafeNet Ghana - WiFi IDS v0.1     ║
  ║   Module 2 - Packet Analysis        ║
  ║   Patrick Idan - GCTU Cybersecurity ║
  ╚══════════════════════════════════════╝
    """)

    print(f"[*] Scapy available: {SCAPY_AVAILABLE}")
    print(f"[*] Available interfaces: {WiFiIDS.list_interfaces()}")

    def on_alert(alert):
        print(f"\n🚨 ALERT: {alert['severity']} — {alert['type']}")
        print(f"   Device : {alert['device_mac']}")
        print(f"   Detail : {alert['detail']}")

    ids = WiFiIDS(alert_callback=on_alert)

    print("\n[*] Starting IDS on all interfaces...")
    print("[*] Press Ctrl+C to stop\n")

    ids.start()

    try:
        while True:
            time.sleep(10)
            status = ids.get_status()
            print(f"[STATUS] Packets: {status['packets_seen']} | Alerts: {status['alerts_total']} | Running: {status['running']}")
    except KeyboardInterrupt:
        ids.stop()
        print("\n[*] IDS stopped.")
        print(f"[*] Final stats: {json.dumps(ids.get_stats(), indent=2)}")
