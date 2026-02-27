import streamlit as st
import json
from collections import defaultdict
import requests as req

st.set_page_config(page_title="Evil Twin WiFi Detector", page_icon="🔍", layout="wide")

# ─── Inject the exact same CSS as your HTML template ───────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600;700&display=swap');

/* Hide default Streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 0 !important; max-width: 100% !important; }
.stApp { background: #0f0f1a; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; }

/* ── Header ── */
.etd-header {
  background: #1a1a2e;
  padding: 24px 40px;
  border-bottom: 2px solid #e94560;
  margin-bottom: 0;
}
.etd-header h1 { color: #e94560; font-size: 1.8rem; margin: 0; }
.etd-header p  { color: #888; margin-top: 6px; font-size: 0.95rem; }

/* ── Container wrapper ── */
.etd-container { max-width: 1000px; margin: 40px auto; padding: 0 20px; }

/* ── Steps bar ── */
.steps { display: flex; gap: 0; margin-bottom: 30px; }
.step {
  flex: 1; text-align: center; padding: 16px 10px;
  background: #12122a; position: relative;
}
.step:not(:last-child)::after {
  content: "→"; position: absolute; right: -10px; top: 50%;
  transform: translateY(-50%); color: #3a3a5a; font-size: 1.2rem; z-index: 1;
}
.step .snum { font-size: 1.4rem; }
.step .stxt { font-size: 0.78rem; color: #888; margin-top: 4px; }

/* ── Card ── */
.etd-card {
  background: #1a1a2e;
  border-radius: 14px;
  padding: 30px;
  margin-bottom: 24px;
  border: 1px solid #2a2a4a;
}
.etd-card h2 {
  color: #a0a8ff; font-size: 0.9rem;
  text-transform: uppercase; letter-spacing: 1px;
  margin-bottom: 20px;
}

/* ── Upload zone ── */
.upload-zone {
  border: 2px dashed #3a3a6a; border-radius: 12px;
  padding: 40px; text-align: center;
  transition: border-color 0.2s;
}
.upload-zone span { font-size: 2.5rem; display: block; }
.upload-zone p { color: #666; margin-top: 10px; font-size: 0.9rem; }

/* ── Streamlit inputs override ── */
.stTextInput > div > div > input {
  background: #0f0f1a !important;
  border: 1px solid #3a3a5a !important;
  border-radius: 8px !important;
  color: #e0e0e0 !important;
  padding: 11px 14px !important;
  font-size: 0.95rem !important;
}
.stTextInput > div > div > input::placeholder { color: #555 !important; }

/* ── File uploader override ── */
.stFileUploader > div {
  background: #12122a !important;
  border: 2px dashed #3a3a6a !important;
  border-radius: 12px !important;
}
.stFileUploader label { color: #666 !important; }

/* ── Analyze button ── */
.stButton > button {
  background: #e94560 !important;
  color: white !important;
  border: none !important;
  border-radius: 8px !important;
  padding: 14px 24px !important;
  font-size: 1rem !important;
  font-weight: 600 !important;
  width: 100% !important;
  margin-top: 8px;
  transition: background 0.2s;
}
.stButton > button:hover { background: #c73550 !important; }

/* ── Stats ── */
.stats { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
.stat-card {
  flex: 1; min-width: 140px; padding: 20px;
  border-radius: 12px; text-align: center;
  background: #12122a; border: 1px solid #2a2a4a;
}
.stat-card .num  { font-size: 2rem; font-weight: 700; }
.stat-card .lbl  { font-size: 0.8rem; color: #666; margin-top: 4px; }
.stat-card.red    .num { color: #ff5555; }
.stat-card.yellow .num { color: #ffcc55; }
.stat-card.green  .num { color: #00d4aa; }
.stat-card.blue   .num { color: #a0a8ff; }

/* ── Alert box ── */
.alert-box {
  background: #2a1a1a; border-left: 4px solid #e94560;
  border-radius: 8px; padding: 14px 16px;
  margin-bottom: 10px; color: #ff8080; font-size: 0.9rem;
}

/* ── Table ── */
.etd-table { width: 100%; border-collapse: collapse; font-size: 0.87rem; }
.etd-table th {
  text-align: left; padding: 11px 12px;
  background: #12122a; color: #6060aa;
  text-transform: uppercase; font-size: 0.73rem; letter-spacing: 0.5px;
}
.etd-table td { padding: 13px 12px; border-bottom: 1px solid #1e1e3a; vertical-align: top; }
.etd-table tr:hover td { background: #1e1e35; }

.badge {
  padding: 4px 12px; border-radius: 20px;
  font-size: 0.78rem; font-weight: 600; white-space: nowrap;
}
.badge.legitimate { background: #0d3a2a; color: #00d4aa; }
.badge.evil_twin  { background: #3a0d0d; color: #ff5555; }
.badge.suspicious { background: #2a2a0d; color: #ffcc55; }

.reason-tag {
  display: inline-block; background: #1e1e35;
  padding: 2px 8px; border-radius: 4px;
  font-size: 0.75rem; color: #888; margin: 2px 2px 0 0;
}
.risk-bar-wrap { display: flex; align-items: center; gap: 8px; }
.risk-bar { height: 6px; border-radius: 3px; background: #1e1e3a; flex: 1; min-width: 60px; }
.risk-fill { height: 100%; border-radius: 3px; }

.file-info {
  margin-top: 12px; padding: 10px 14px;
  background: #0f0f2a; border-radius: 8px;
  font-size: 0.85rem; color: #a0a8ff;
}
.empty-msg { text-align: center; color: #444; padding: 40px; }
</style>
""", unsafe_allow_html=True)


# ─── Helper Functions ──────────────────────────────────────────────────────────
def get_vendor(mac):
    try:
        r = req.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text.strip()
    except:
        return "Unknown"

def analyze_networks(networks, target_ssid, known_bssid=""):
    ssid_groups = defaultdict(list)
    for n in networks:
        ssid_groups[n["ssid"]].append(n)

    results, alerts = [], []

    for ssid, aps in ssid_groups.items():
        if target_ssid and ssid != target_ssid:
            continue

        for ap in aps:
            bssid    = ap.get("bssid", "").upper().strip()
            vendor   = get_vendor(bssid)
            security = ap.get("security", "Unknown")
            signal   = ap.get("signal", "N/A")
            channel  = ap.get("channel", "N/A")

            risk_score, reasons = 0, []

            if known_bssid and bssid != known_bssid.upper().strip():
                risk_score += 50
                reasons.append("BSSID doesn't match known legitimate AP")
            if len(aps) > 1:
                risk_score += 30
                reasons.append(f"{len(aps)} APs broadcasting same SSID")
            if "Open" in security or security in ("", "None"):
                risk_score += 20
                reasons.append("Open network (no password/encryption)")
            if vendor in ("Unknown", ""):
                risk_score += 10
                reasons.append("Unknown hardware vendor")

            if risk_score >= 50:
                status, label = "evil_twin",  "🔴 Likely Evil Twin"
            elif risk_score >= 20:
                status, label = "suspicious", "⚠️ Suspicious"
            else:
                status, label = "legitimate", "✅ Likely Legitimate"

            results.append({
                "ssid": ssid, "bssid": bssid, "signal": signal,
                "security": security, "channel": channel, "vendor": vendor,
                "status": status, "label": label,
                "risk_score": risk_score, "reasons": reasons
            })

        if len(aps) > 1:
            alerts.append(f"⚠️ '{ssid}' is being broadcast by {len(aps)} different APs — possible Evil Twin!")

    return results, alerts


# ─── UI ───────────────────────────────────────────────────────────────────────

# Header
st.markdown("""
<div class="etd-header">
  <h1>🔍 Evil Twin WiFi Detector</h1>
  <p>Upload your WiFi scan data — we'll tell you which network is legitimate</p>
</div>
""", unsafe_allow_html=True)

# Container start
st.markdown('<div class="etd-container">', unsafe_allow_html=True)

# Steps bar
st.markdown("""
<div class="steps">
  <div class="step"><div class="snum">1️⃣</div><div class="stxt">Run scan script on your device</div></div>
  <div class="step"><div class="snum">2️⃣</div><div class="stxt">Download the JSON file it creates</div></div>
  <div class="step"><div class="snum">3️⃣</div><div class="stxt">Upload it here</div></div>
  <div class="step"><div class="snum">4️⃣</div><div class="stxt">See which WiFi is real or fake</div></div>
</div>
""", unsafe_allow_html=True)

# Upload Card
st.markdown('<div class="etd-card"><h2>📁 Upload Scan File</h2>', unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    "Click to upload wifi_scan.json or drag & drop",
    type=["json"],
    label_visibility="visible"
)

if uploaded_file:
    size_kb = len(uploaded_file.getvalue()) / 1024
    st.markdown(f'<div class="file-info">📄 {uploaded_file.name} &nbsp;({size_kb:.1f} KB)</div>', unsafe_allow_html=True)

col1, col2 = st.columns(2)
with col1:
    target_ssid = st.text_input("", placeholder="WiFi name to check (e.g. HomeNetwork) — leave blank to check all", label_visibility="collapsed")
with col2:
    known_bssid = st.text_input("", placeholder="Known real BSSID (optional) e.g. AA:BB:CC:DD:EE:FF", label_visibility="collapsed")

analyze_clicked = st.button("🔍 Analyze Now")
st.markdown('</div>', unsafe_allow_html=True)  # close card


# ─── Results ─────────────────────────────────────────────────────────────────
if analyze_clicked:
    if not uploaded_file:
        st.markdown('<div class="alert-box">⚠️ Please upload a wifi_scan.json file first!</div>', unsafe_allow_html=True)
    else:
        try:
            uploaded_file.seek(0)
            networks = json.load(uploaded_file)
        except Exception:
            st.markdown('<div class="alert-box">❌ Invalid JSON file. Please check the format.</div>', unsafe_allow_html=True)
            st.stop()

        with st.spinner("Analyzing networks..."):
            results, alerts = analyze_networks(networks, target_ssid, known_bssid)

        # ── Stats ──
        evil  = sum(1 for r in results if r["status"] == "evil_twin")
        susp  = sum(1 for r in results if r["status"] == "suspicious")
        legit = sum(1 for r in results if r["status"] == "legitimate")

        st.markdown(f"""
        <div class="stats">
          <div class="stat-card blue">
            <div class="num">{len(results)}</div>
            <div class="lbl">Total APs Found</div>
          </div>
          <div class="stat-card red">
            <div class="num">{evil}</div>
            <div class="lbl">Evil Twins</div>
          </div>
          <div class="stat-card yellow">
            <div class="num">{susp}</div>
            <div class="lbl">Suspicious</div>
          </div>
          <div class="stat-card green">
            <div class="num">{legit}</div>
            <div class="lbl">Legitimate</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Alerts ──
        if alerts:
            st.markdown('<div class="etd-card"><h2>⚠️ Alerts</h2>', unsafe_allow_html=True)
            for a in alerts:
                st.markdown(f'<div class="alert-box">{a}</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # ── Results Table ──
        st.markdown('<div class="etd-card"><h2>📊 Analysis Results</h2>', unsafe_allow_html=True)

        if not results:
            st.markdown('<div class="empty-msg">No matching networks found</div>', unsafe_allow_html=True)
        else:
            rows_html = ""
            for r in results:
                pct   = min(r["risk_score"], 100)
                color = "#ff5555" if r["status"] == "evil_twin" else "#ffcc55" if r["status"] == "suspicious" else "#00d4aa"
                tags  = "".join(f'<span class="reason-tag">{x}</span>' for x in r["reasons"])

                rows_html += f"""
                <tr>
                  <td><strong>{r['ssid']}</strong></td>
                  <td><code style="font-size:0.82rem">{r['bssid']}</code></td>
                  <td>{r['security']}</td>
                  <td>{r['signal']}</td>
                  <td>{r['vendor']}</td>
                  <td>
                    <div class="risk-bar-wrap">
                      <div class="risk-bar">
                        <div class="risk-fill" style="width:{pct}%;background:{color}"></div>
                      </div>
                      <span style="font-size:0.78rem;color:{color}">{pct}</span>
                    </div>
                    <div>{tags}</div>
                  </td>
                  <td><span class="badge {r['status']}">{r['label']}</span></td>
                </tr>
                """

            st.markdown(f"""
            <table class="etd-table">
              <thead>
                <tr>
                  <th>SSID</th><th>BSSID</th><th>Security</th>
                  <th>Signal</th><th>Vendor</th><th>Risk</th><th>Status</th>
                </tr>
              </thead>
              <tbody>{rows_html}</tbody>
            </table>
            """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)  # close card

# Sample JSON format expander
with st.expander("📄 Expected JSON format"):
    st.code('''[
  {
    "ssid": "MyNetwork",
    "bssid": "AA:BB:CC:DD:EE:FF",
    "signal": -55,
    "security": "WPA2",
    "channel": 6
  }
]''', language="json")

st.markdown('</div>', unsafe_allow_html=True)  # close container