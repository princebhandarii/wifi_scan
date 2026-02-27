import streamlit as st
import streamlit.components.v1 as components
import json
from collections import defaultdict
import requests as req

st.set_page_config(page_title="Evil Twin WiFi Detector", page_icon="🔍", layout="wide")

# ─── Global CSS injected into Streamlit ───────────────────────────────────────
st.markdown("""
<style>
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 0 !important; max-width: 100% !important; }
.stApp { background: #0f0f1a; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; }

.etd-header {
  background: #1a1a2e; padding: 24px 40px;
  border-bottom: 2px solid #e94560; margin-bottom: 0;
}
.etd-header h1 { color: #e94560; font-size: 1.8rem; margin: 0; }
.etd-header p  { color: #888; margin-top: 6px; font-size: 0.95rem; }

.steps { display: flex; margin-bottom: 30px; }
.step  { flex:1; text-align:center; padding:16px 10px; background:#12122a; position:relative; }
.step:not(:last-child)::after {
  content:"→"; position:absolute; right:-10px; top:50%;
  transform:translateY(-50%); color:#3a3a5a; font-size:1.2rem; z-index:1;
}
.step .snum { font-size:1.4rem; }
.step .stxt { font-size:0.78rem; color:#888; margin-top:4px; }

.etd-card {
  background:#1a1a2e; border-radius:14px;
  padding:30px; margin-bottom:24px; border:1px solid #2a2a4a;
}
.etd-card h2 {
  color:#a0a8ff; font-size:0.9rem;
  text-transform:uppercase; letter-spacing:1px; margin-bottom:20px;
}

[data-testid="stFileUploader"] section {
  background:#12122a !important;
  border:2px dashed #3a3a6a !important;
  border-radius:12px !important;
}
[data-testid="stFileUploaderDropzoneInstructions"] { color:#666 !important; }

.stTextInput > div > div > input {
  background:#0f0f1a !important; border:1px solid #3a3a5a !important;
  border-radius:8px !important; color:#e0e0e0 !important;
  padding:11px 14px !important; font-size:0.95rem !important;
}
.stTextInput > div > div > input::placeholder { color:#555 !important; }
.stTextInput label { color:#666 !important; font-size:0.85rem !important; }

.stButton > button {
  background:#e94560 !important; color:white !important;
  border:none !important; border-radius:8px !important;
  padding:14px 24px !important; font-size:1rem !important;
  font-weight:600 !important; width:100% !important; margin-top:8px;
}
.stButton > button:hover { background:#c73550 !important; }

.stats { display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }
.stat-card {
  flex:1; min-width:140px; padding:20px; border-radius:12px;
  text-align:center; background:#12122a; border:1px solid #2a2a4a;
}
.stat-card .num { font-size:2rem; font-weight:700; }
.stat-card .lbl { font-size:0.8rem; color:#666; margin-top:4px; }
.stat-card.red    .num { color:#ff5555; }
.stat-card.yellow .num { color:#ffcc55; }
.stat-card.green  .num { color:#00d4aa; }
.stat-card.blue   .num { color:#a0a8ff; }

.alert-box {
  background:#2a1a1a; border-left:4px solid #e94560;
  border-radius:8px; padding:14px 16px;
  margin-bottom:10px; color:#ff8080; font-size:0.9rem;
}
.file-info {
  margin-top:12px; padding:10px 14px; background:#0f0f2a;
  border-radius:8px; font-size:0.85rem; color:#a0a8ff;
}
</style>
""", unsafe_allow_html=True)


# ─── Helpers ──────────────────────────────────────────────────────────────────
def get_vendor(mac):
    try:
        r = req.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if r.status_code == 200:
            return r.text.strip()
        return "Unknown"
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
            alerts.append(f"⚠️ '{ssid}' is broadcast by {len(aps)} different APs — possible Evil Twin!")

    return results, alerts


def build_table_html(results):
    """
    Build the full results table as a self-contained HTML page.
    Uses components.html() to bypass Streamlit's HTML sanitizer
    which strips <table>, <tr>, <td> tags.
    """
    rows = ""
    for r in results:
        pct   = min(r["risk_score"], 100)
        color = "#ff5555" if r["status"] == "evil_twin" else "#ffcc55" if r["status"] == "suspicious" else "#00d4aa"
        tags  = "".join(f'<span class="reason-tag">{x}</span>' for x in r["reasons"])
        rows += f"""
        <tr>
          <td><strong>{r['ssid']}</strong></td>
          <td><code>{r['bssid']}</code></td>
          <td>{r['security']}</td>
          <td>{r['signal']}</td>
          <td>{r['vendor']}</td>
          <td>
            <div class="risk-bar-wrap">
              <div class="risk-bar">
                <div class="risk-fill" style="width:{pct}%;background:{color}"></div>
              </div>
              <span style="font-size:0.78rem;color:{color};min-width:24px">{pct}</span>
            </div>
            <div style="margin-top:4px">{tags}</div>
          </td>
          <td><span class="badge {r['status']}">{r['label']}</span></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #1a1a2e; color: #e0e0e0;
    font-family: 'Segoe UI', sans-serif; font-size: 0.87rem;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    text-align: left; padding: 11px 12px; background: #12122a;
    color: #6060aa; text-transform: uppercase;
    font-size: 0.73rem; letter-spacing: 0.5px; font-weight: 600;
  }}
  td {{ padding: 13px 12px; border-bottom: 1px solid #1e1e3a; vertical-align: top; }}
  tr:hover td {{ background: #1e1e35; }}
  code {{ font-size: 0.82rem; color: #a0a8ff; }}
  .badge {{
    padding: 4px 12px; border-radius: 20px;
    font-size: 0.78rem; font-weight: 600; white-space: nowrap;
  }}
  .badge.legitimate {{ background: #0d3a2a; color: #00d4aa; }}
  .badge.evil_twin  {{ background: #3a0d0d; color: #ff5555; }}
  .badge.suspicious {{ background: #2a2a0d; color: #ffcc55; }}
  .reason-tag {{
    display: inline-block; background: #1e1e35;
    padding: 2px 8px; border-radius: 4px;
    font-size: 0.75rem; color: #888; margin: 2px 2px 0 0;
  }}
  .risk-bar-wrap {{ display: flex; align-items: center; gap: 8px; }}
  .risk-bar {{ height: 6px; border-radius: 3px; background: #1e1e3a; flex: 1; min-width: 60px; }}
  .risk-fill {{ height: 100%; border-radius: 3px; }}
</style>
</head>
<body>
<table>
  <thead>
    <tr>
      <th>SSID</th><th>BSSID</th><th>Security</th>
      <th>Signal</th><th>Vendor</th><th>Risk</th><th>Status</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
</body>
</html>"""


# ─── Session state ─────────────────────────────────────────────────────────────
if "results"  not in st.session_state: st.session_state.results  = None
if "alerts"   not in st.session_state: st.session_state.alerts   = None
if "analyzed" not in st.session_state: st.session_state.analyzed = False


# ─── HEADER ───────────────────────────────────────────────────────────────────
st.markdown("""
<div class="etd-header">
  <h1>🔍 Evil Twin WiFi Detector</h1>
  <p>Upload your WiFi scan data — we'll tell you which network is legitimate</p>
</div>
""", unsafe_allow_html=True)

# ─── STEPS ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="max-width:1000px;margin:40px auto 0;padding:0 20px">
<div class="steps">
  <div class="step"><div class="snum">1️⃣</div><div class="stxt">Run scan script on your device</div></div>
  <div class="step"><div class="snum">2️⃣</div><div class="stxt">Download the JSON file it creates</div></div>
  <div class="step"><div class="snum">3️⃣</div><div class="stxt">Upload it here</div></div>
  <div class="step"><div class="snum">4️⃣</div><div class="stxt">See which WiFi is real or fake</div></div>
</div>
</div>
""", unsafe_allow_html=True)

# ─── UPLOAD CARD ──────────────────────────────────────────────────────────────
st.markdown('<div style="max-width:1000px;margin:0 auto;padding:0 20px">', unsafe_allow_html=True)
st.markdown('<div class="etd-card"><h2>📁 Upload Scan File</h2>', unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    "Upload wifi_scan.json",
    type=["json"],
    label_visibility="collapsed"
)

if uploaded_file is not None:
    size_kb = len(uploaded_file.getvalue()) / 1024
    st.markdown(
        f'<div class="file-info">📄 {uploaded_file.name} &nbsp;&nbsp;({size_kb:.1f} KB) — ✅ Ready</div>',
        unsafe_allow_html=True
    )

col1, col2 = st.columns(2)
with col1:
    target_ssid = st.text_input(
        "Target SSID",
        placeholder="WiFi name to check — leave blank for all",
        label_visibility="collapsed"
    )
with col2:
    known_bssid = st.text_input(
        "Known BSSID",
        placeholder="Known real BSSID (optional) e.g. AA:BB:CC:DD:EE:FF",
        label_visibility="collapsed"
    )

analyze_clicked = st.button("🔍 Analyze Now")
st.markdown("</div>", unsafe_allow_html=True)  # close etd-card

# ─── ANALYZE ──────────────────────────────────────────────────────────────────
if analyze_clicked:
    if uploaded_file is None:
        st.markdown('<div class="alert-box">⚠️ Please upload a wifi_scan.json file first!</div>', unsafe_allow_html=True)
        st.session_state.analyzed = False
    else:
        try:
            raw = uploaded_file.getvalue()
            networks = json.loads(raw.decode("utf-8"))
        except Exception as e:
            st.markdown(f'<div class="alert-box">❌ Invalid JSON: {e}</div>', unsafe_allow_html=True)
            st.stop()

        with st.spinner("🔍 Analyzing networks..."):
            results, alerts = analyze_networks(networks, target_ssid, known_bssid)

        st.session_state.results  = results
        st.session_state.alerts   = alerts
        st.session_state.analyzed = True

# ─── RESULTS ──────────────────────────────────────────────────────────────────
if st.session_state.analyzed and st.session_state.results is not None:
    results = st.session_state.results
    alerts  = st.session_state.alerts

    evil  = sum(1 for r in results if r["status"] == "evil_twin")
    susp  = sum(1 for r in results if r["status"] == "suspicious")
    legit = sum(1 for r in results if r["status"] == "legitimate")

    # Stats cards
    st.markdown(f"""
    <div class="stats">
      <div class="stat-card blue"><div class="num">{len(results)}</div><div class="lbl">Total APs Found</div></div>
      <div class="stat-card red"><div class="num">{evil}</div><div class="lbl">Evil Twins</div></div>
      <div class="stat-card yellow"><div class="num">{susp}</div><div class="lbl">Suspicious</div></div>
      <div class="stat-card green"><div class="num">{legit}</div><div class="lbl">Legitimate</div></div>
    </div>
    """, unsafe_allow_html=True)

    # Alerts
    if alerts:
        alert_html = "".join(f'<div class="alert-box">{a}</div>' for a in alerts)
        st.markdown(f'<div class="etd-card"><h2>⚠️ Alerts</h2>{alert_html}</div>', unsafe_allow_html=True)

    # ── Results Table via components.html() ──
    # This is THE FIX: components.html renders real HTML in an iframe,
    # bypassing Streamlit's sanitizer that strips table/tr/td tags.
    if not results:
        st.markdown('<div class="alert-box">No matching networks found.</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="etd-card"><h2>📊 Analysis Results</h2></div>', unsafe_allow_html=True)
        table_html = build_table_html(results)
        row_height = 80  # px per row estimate
        table_height = 60 + (len(results) * row_height)
        components.html(table_html, height=table_height, scrolling=False)

# ─── Sample JSON ──────────────────────────────────────────────────────────────
with st.expander("📄 Expected JSON format — click to expand"):
    st.code('''[
  {
    "ssid": "MyNetwork",
    "bssid": "AA:BB:CC:DD:EE:FF",
    "signal": -55,
    "security": "WPA2",
    "channel": 6
  },
  {
    "ssid": "MyNetwork",
    "bssid": "11:22:33:44:55:66",
    "signal": -70,
    "security": "Open",
    "channel": 11
  }
]''', language="json")

st.markdown("</div>", unsafe_allow_html=True)
