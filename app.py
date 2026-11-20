
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit.components.v1 as components
import time
import random
from pathlib import Path
from datetime import datetime

from modules.log_processor import LogProcessor
from modules.threat_detector import ThreatDetector
from modules.incident_correlator import IncidentCorrelator
from modules.sorting_algorithms import SortingAlgorithms
from modules.database_manager import DatabaseManager
from modules.authentication import AuthenticationService


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="NEXUS | Cyber Intelligence",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE_DIR = Path(__file__).resolve().parent
CSV_PATH = BASE_DIR / "data" / "security_logs.csv"


# =========================================================
# FUTURISTIC DESIGN SYSTEM
# =========================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Orbitron:wght@400;500;600;700;800&display=swap');

:root {
    --bg: #070b14;
    --panel: #0d1524;
    --cyan: #00e5ff;
    --blue: #5577ff;
    --purple: #a855f7;
    --text: #edf5ff;
    --muted: #8293aa;
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(ellipse at 10% 10%, rgba(0,229,255,.09), transparent 35%),
        radial-gradient(ellipse at 90% 20%, rgba(91,80,255,.10), transparent 35%),
        #070b14;
    color: var(--text);
}

/* Hide Streamlit default elements */

#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header[data-testid="stHeader"] {
    background: transparent;
}

/* Main container */

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1500px;
}

/* Sidebar */

section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0c1422, #080d17);
    border-right: 1px solid rgba(0,229,255,.15);
}

section[data-testid="stSidebar"] * {
    color: #dcecff;
}

section[data-testid="stSidebar"] .stRadio label {
    padding: 10px 13px;
    border-radius: 10px;
    transition: .25s;
}

section[data-testid="stSidebar"] .stRadio label:hover {
    background: rgba(0,229,255,.10);
}

/* Typography */

.nexus-logo {
    font-family: 'Orbitron', sans-serif;
    font-size: 27px;
    font-weight: 800;
    letter-spacing: 4px;
    color: #00e5ff;
    text-shadow: 0 0 18px rgba(0,229,255,.65);
}

.nexus-sub {
    color: #8293aa;
    font-size: 10px;
    letter-spacing: 3px;
    margin-top: -4px;
}

.page-title {
    font-family: 'Orbitron', sans-serif;
    font-size: clamp(24px, 3vw, 38px);
    font-weight: 700;
    letter-spacing: 1px;
    color: #effaff;
    margin-bottom: 5px;
}

.page-subtitle {
    color: #8394ab;
    font-size: 13px;
    margin-bottom: 24px;
}

.section-title {
    font-family: 'Orbitron', sans-serif;
    font-size: 15px;
    letter-spacing: 1px;
    color: #dffaff;
    margin-bottom: 15px;
}

/* Glass cards */

.glass-card {
    background: linear-gradient(
        145deg,
        rgba(21,35,55,.88),
        rgba(10,18,32,.90)
    );
    border: 1px solid rgba(0,229,255,.16);
    border-radius: 18px;
    padding: 21px;
    box-shadow:
        0 12px 35px rgba(0,0,0,.24),
        inset 0 1px 0 rgba(255,255,255,.04);
    transition: all .35s ease;
    position: relative;
    overflow: hidden;
}

.glass-card:hover {
    transform: translateY(-6px) perspective(800px) rotateX(2deg);
    border-color: rgba(0,229,255,.55);
    box-shadow:
        0 18px 40px rgba(0,229,255,.10),
        0 0 25px rgba(0,229,255,.08);
}

.metric-label {
    color: #8ea1b9;
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}

.metric-value {
    font-family: 'Orbitron', sans-serif;
    color: #f4fbff;
    font-size: 30px;
    font-weight: 700;
    margin-top: 9px;
}

.metric-icon {
    font-size: 23px;
    margin-bottom: 12px;
}

.metric-foot {
    color: #00d9b2;
    font-size: 11px;
    margin-top: 7px;
}

/* Hero */

.hero-card {
    position: relative;
    border-radius: 22px;
    overflow: hidden;
    padding: 27px;
    min-height: 190px;
    background:
        radial-gradient(circle at 80% 20%, rgba(0,229,255,.18), transparent 35%),
        linear-gradient(120deg, #101f35, #10152b 65%, #101c35);
    border: 1px solid rgba(0,229,255,.23);
    box-shadow: 0 15px 45px rgba(0,0,0,.3);
}

.hero-card:after {
    content: "";
    position: absolute;
    top: 0;
    left: -100%;
    width: 60%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,.045), transparent);
    transform: skewX(-20deg);
    animation: shine 7s infinite;
}

@keyframes shine {
    0% {left:-100%;}
    40%,100% {left:150%;}
}

.hero-kicker {
    color: #00e5ff;
    font-size: 10px;
    letter-spacing: 3px;
    font-weight: 700;
}

.hero-heading {
    font-family: 'Orbitron', sans-serif;
    font-size: clamp(20px, 3vw, 32px);
    color: white;
    margin-top: 12px;
    font-weight: 700;
}

.hero-description {
    color: #a9bdd1;
    font-size: 12px;
    max-width: 550px;
    line-height: 1.8;
}

/* Status */

.status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    background: #00e5a8;
    border-radius: 50%;
    margin-right: 8px;
    box-shadow: 0 0 12px #00e5a8;
    animation: pulse 1.5s infinite;
}

@keyframes pulse {
    0%,100% {opacity:1; box-shadow:0 0 5px #00e5a8;}
    50% {opacity:.4; box-shadow:0 0 18px #00e5a8;}
}

/* Buttons */

.stButton button {
    background: linear-gradient(100deg, #087fbd, #525bdf);
    color: white;
    border: 1px solid rgba(0,229,255,.3);
    border-radius: 10px;
    font-weight: 600;
    transition: .3s;
}

.stButton button:hover {
    transform: translateY(-2px);
    box-shadow: 0 0 22px rgba(0,229,255,.25);
    border-color: #00e5ff;
}

/* Dataframes */

[data-testid="stDataFrame"] {
    border: 1px solid rgba(0,229,255,.15);
    border-radius: 12px;
}

/* Dividers */

hr {
    border-color: rgba(0,229,255,.12);
}

/* Inputs */

.stSelectbox div[data-baseweb="select"],
.stTextInput input {
    background-color: #101b2b;
    color: white;
}

/* Responsive */

@media(max-width: 768px) {
    .metric-value {font-size:23px;}
    .hero-card {padding:20px;}
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# NEXUS AUTHENTICATION AND ROLE CONTROL
# =========================================================

def _client_ip():
    try: return str(st.context.ip_address or "Unknown")
    except Exception: return "Unknown"

def _client_device():
    try: return str(st.context.headers.get("User-Agent", "Browser"))[:220]
    except Exception: return "Browser"

def _db_call(method, *args):
    db=DatabaseManager()
    try: return getattr(db,method)(*args)
    finally: db.close()

def _bootstrap_admin():
    # Cloud admin is created/updated only from private Streamlit Secrets.
    try:
        cfg=st.secrets.get("admin", {})
    except Exception:
        return  # No secrets is normal for local development.
    username=cfg.get("username", "")
    password=cfg.get("password", "")
    if username and password:
        service=AuthenticationService()
        try: service.create_admin(username,password)
        except Exception as error: st.error(f"Admin setup needs attention: {error}")
        finally: service.close()

def _show_authentication():
    st.markdown("<div style='height:3vh'></div>",unsafe_allow_html=True)
    left,center,right=st.columns([1,1.5,1],gap="large")
    with left:
        st.markdown("<div class='glass-card'><div class='metric-label'>NEXUS ACCESS</div><h2 style='color:#91f2df'>SECURE GATEWAY</h2><p>Identity verification</p><p>Role-based access</p><p>Session monitoring</p><p>Threat intelligence</p></div>",unsafe_allow_html=True)
    with center:
        st.markdown("<div style='text-align:center'><div class='page-title'>NEXUS</div><div class='page-subtitle'>SMART USER ACCESS CONTROL & CYBER THREAT DETECTION</div></div>",unsafe_allow_html=True)
        render_3d_globe()
        mode=st.radio("ACCESS PORTAL",["Login","Create Account"],horizontal=True)
        if mode=="Login":
            with st.form("nexus_login"):
                username=st.text_input("Username")
                password=st.text_input("Password",type="password")
                submit=st.form_submit_button("SECURE LOGIN",use_container_width=True)
            if submit:
                service=AuthenticationService()
                try: result=service.login(username,password,_client_ip(),_client_device())
                except Exception as error: st.error(f"Authentication error: {error}"); result={"success":False}
                finally: service.close()
                if result.get("success"):
                    st.session_state["nexus_token"]=result["token"]
                    st.rerun()
                else: st.error(result.get("message","Login failed."))
        else:
            with st.form("nexus_register"):
                username=st.text_input("Choose username")
                email=st.text_input("Email (optional)")
                password=st.text_input("Create password",type="password")
                confirm=st.text_input("Confirm password",type="password")
                submit=st.form_submit_button("CREATE ACCOUNT",use_container_width=True)
            if submit:
                if password!=confirm: st.error("Passwords do not match.")
                else:
                    service=AuthenticationService()
                    try: service.register_user(username,email,password); st.success("Account created. You can now log in.")
                    except Exception as error: st.error(str(error))
                    finally: service.close()
    with right:
        st.markdown("<div class='glass-card'><div class='metric-label'>SYSTEM STATUS</div><h3 style='color:#91f2df'>● ONLINE</h3><p>Protected workspace</p><p>Account security</p><p>Security event logging</p></div>",unsafe_allow_html=True)
    st.stop()


# =========================================================
# LOAD PROJECT DATA
# =========================================================

@st.cache_data
def load_project_data():

    if not CSV_PATH.exists():
        return None, [], [], [], "CSV file not found"

    try:
        processor = LogProcessor()
        logs = processor.load_logs(str(CSV_PATH))

        if logs is None:
            return None, [], [], [], "Unable to load CSV"

        events = processor.process_logs()

        detector = ThreatDetector()
        threats = detector.detect_threats(events)

        correlator = IncidentCorrelator()
        incidents = correlator.correlate_events(events)

        return logs, events, threats, incidents, None

    except Exception as error:
        return None, [], [], [], str(error)


logs, events, threats, incidents, load_error = load_project_data()


# =========================================================
# GENERAL HELPERS
# =========================================================

def page_header(title, subtitle):
    st.markdown(f"""
    <div class="page-title">{title}</div>
    <div class="page-subtitle">{subtitle}</div>
    """, unsafe_allow_html=True)


def metric_card(icon, label, value, foot="SYSTEM ANALYTICS"):
    st.markdown(f"""
    <div class="glass-card">
        <div class="metric-icon">{icon}</div>
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-foot">↗ {foot}</div>
    </div>
    """, unsafe_allow_html=True)


def panel_title(title):
    st.markdown(
        f'<div class="section-title">{title}</div>',
        unsafe_allow_html=True
    )


def style_chart(fig, height=350):
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c7d9ec", family="Inter"),
        margin=dict(l=10, r=10, t=35, b=10),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#c7d9ec")
        ),
        xaxis=dict(
            gridcolor="rgba(130,160,190,.10)",
            zerolinecolor="rgba(130,160,190,.10)"
        ),
        yaxis=dict(
            gridcolor="rgba(130,160,190,.10)",
            zerolinecolor="rgba(130,160,190,.10)"
        )
    )
    return fig


# =========================================================
# 3D CYBER GLOBE - THREE.JS
# =========================================================

def render_3d_globe():
    """Responsive animated 3D-style wave network field."""
    html = r"""
    <div id="nxwave" style="height:390px;width:100%;position:relative;overflow:hidden;border:1px solid rgba(0,210,205,.22);border-radius:20px;background:radial-gradient(ellipse at 50% 0%,rgba(0,170,165,.18),transparent 58%),linear-gradient(150deg,#071b22,#07101b 72%);">
      <canvas id="nxwavecanvas" style="width:100%;height:100%;display:block"></canvas>
      <div style="position:absolute;top:17px;left:18px;color:#91f2df;font:800 10px Arial;letter-spacing:2px">NEXUS / LIVE NETWORK FIELD</div>
      <div style="position:absolute;bottom:15px;left:18px;color:#77d9ca;font:700 9px Arial;letter-spacing:1.5px">● SECURITY VISUALIZATION ACTIVE</div>
      <div style="position:absolute;bottom:15px;right:18px;color:#8daab7;font:700 9px Arial;letter-spacing:1.5px">3D WAVE MESH</div>
    </div>
    <script>
    (()=>{const box=document.getElementById('nxwave'),c=document.getElementById('nxwavecanvas');if(!box||!c)return;const x=c.getContext('2d');let w=0,h=0,t=0,raf;
    function size(){const r=box.getBoundingClientRect(),d=Math.min(devicePixelRatio||1,2);w=r.width;h=r.height;c.width=w*d;c.height=h*d;x.setTransform(d,0,0,d,0,0)}
    function draw(){t+=.012;x.clearRect(0,0,w,h);const rows=25,cols=Math.max(38,Math.floor(w/14)),pts=[];for(let r=0;r<rows;r++){let row=[],dep=r/(rows-1);for(let q=0;q<=cols;q++){let xx=(q/cols-.5)*w*1.35,yy=h*.18+dep*dep*h*.82+(Math.sin(q*.19+t*1.4+r*.22)*13+Math.cos(q*.08-t+r*.3)*9)*(.25+dep);row.push({x:w/2+xx*(.22+dep),y:yy,dep})}pts.push(row)}
    let g=x.createRadialGradient(w*.5,h*.5,1,w*.5,h*.5,w*.7);g.addColorStop(0,'rgba(0,190,170,.13)');g.addColorStop(1,'rgba(0,0,0,0)');x.fillStyle=g;x.fillRect(0,0,w,h);
    for(let r=0;r<rows;r++){x.beginPath();pts[r].forEach((p,i)=>i?x.lineTo(p.x,p.y):x.moveTo(p.x,p.y));x.strokeStyle='rgba(55,220,190,'+(.08+pts[r][0].dep*.2)+')';x.lineWidth=.7;x.stroke()}
    for(let q=0;q<=cols;q+=2){x.beginPath();for(let r=0;r<rows;r++){let p=pts[r][q];r?x.lineTo(p.x,p.y):x.moveTo(p.x,p.y)}x.strokeStyle='rgba(65,170,165,.16)';x.stroke()}
    for(let i=0;i<24;i++){let q=Math.floor((i*31+t*7)%cols),r=(i*7)%rows,p=pts[r][q],pulse=(Math.sin(t*3+i)+1)/2;x.beginPath();x.arc(p.x,p.y,1+pulse*2,0,Math.PI*2);x.fillStyle=i%5===0?'#b4ffe8':'#65e1cc';x.shadowBlur=10;x.shadowColor='#45e5c5';x.fill();x.shadowBlur=0}raf=requestAnimationFrame(draw)}
    size();draw();if(window.ResizeObserver)new ResizeObserver(size).observe(box);window.addEventListener('pagehide',()=>cancelAnimationFrame(raf),{once:true})})();
    </script>
    """
    components.html(html, height=405, scrolling=False)


# =========================================================
# NEXUS AUTHENTICATION AND ROLE CONTROL — EXECUTION
# Defined after render_3d_globe so login screen can call it safely.
# =========================================================

_bootstrap_admin()
_current_user = None
_saved_token = st.session_state.get("nexus_token")

if _saved_token:
    service = AuthenticationService()
    try:
        _current_user = service.verify_session(_saved_token)
    finally:
        service.close()

if not _current_user:
    st.session_state.pop("nexus_token", None)
    _show_authentication()


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:
    st.markdown("<div style='padding:15px 5px 20px'><div class='nexus-logo'>NEXUS</div><div class='nexus-sub'>CYBER INTELLIGENCE</div></div>",unsafe_allow_html=True)
    st.caption("SIGNED IN AS")
    st.markdown(f"**{_current_user['username']}**")
    st.caption(_current_user['role'].upper())
    if _current_user['role']=="admin":
        pages=["🌐 Command Center","📡 Security Logs","🛡️ Threat Intelligence","🔗 Incident Correlation","🧬 DSA Laboratory","💾 Database Explorer","📟 Live Login Monitor","👥 User Management","🧾 Audit Logs"]
    else:
        pages=["👤 My Account"]
    selected_page=st.radio("Navigation",pages,label_visibility="collapsed")
    st.markdown("---")
    st.caption("NEXUS • ACCESS CONTROL SYSTEM")
    if st.button("LOG OUT",use_container_width=True):
        token=st.session_state.pop("nexus_token",None)
        if token:
            service=AuthenticationService()
            try: service.logout(token)
            finally: service.close()
        st.rerun()


# =========================================================
# ERROR HANDLING
# =========================================================

if load_error:

    st.error(f"Project data could not be loaded: {load_error}")
    st.info("Please check your CSV file and Python modules.")
    st.stop()


# =========================================================
# PREPARE DATA
# =========================================================

total_logs = len(logs)
total_threats = len(threats)
total_incidents = len(incidents)

high_threats = sum(
    1 for item in threats if item.get("severity") == "HIGH"
)

medium_threats = sum(
    1 for item in threats if item.get("severity") == "MEDIUM"
)

low_threats = sum(
    1 for item in threats if item.get("severity") == "LOW"
)


# =========================================================
# COMMAND CENTER
# =========================================================

if selected_page == "👤 My Account":
    page_header("USER PORTAL", "Your account and security activity")
    st.markdown(f"<div class='glass-card'><div class='metric-label'>AUTHENTICATED USER</div><h2>{_current_user['username']}</h2><div class='metric-foot'>ACCOUNT SESSION ACTIVE</div></div>",unsafe_allow_html=True)
    a,b=st.columns(2); a.metric("ACCOUNT ROLE",_current_user['role'].upper()); b.metric("ACCOUNT STATUS",_current_user['status'].upper())
    st.subheader("Your recent activity")
    own=[e for e in _db_call('get_security_events',200) if (e.get('username') or '').lower()==_current_user['username'].lower()]
    if own: st.dataframe(pd.DataFrame(own),use_container_width=True,hide_index=True)
    else: st.info("No account activity recorded yet.")

elif selected_page == "📟 Live Login Monitor":
    page_header("LIVE LOGIN MONITOR", "Recent NEXUS authentication activity")
    events=_db_call('get_security_events',500); sessions=_db_call('get_active_sessions')
    a,b,c=st.columns(3); a.metric("ACTIVE SESSIONS",len(sessions)); b.metric("SUCCESSFUL LOGINS",sum(e.get('event_type')=='LOGIN' and e.get('status')=='SUCCESS' for e in events)); c.metric("FAILED LOGINS",sum(e.get('event_type')=='LOGIN' and e.get('status')=='FAILED' for e in events))
    st.subheader("Active sessions")
    if sessions: st.dataframe(pd.DataFrame(sessions),use_container_width=True,hide_index=True)
    else: st.info("No active sessions.")
    st.subheader("Recent login events")
    if events: st.dataframe(pd.DataFrame(events),use_container_width=True,hide_index=True)
    else: st.info("No login events yet.")
    if st.button("REFRESH MONITOR"): st.rerun()

elif selected_page == "👥 User Management":
    page_header("USER MANAGEMENT", "Review and control registered accounts")
    users=_db_call('get_all_users')
    if users: st.dataframe(pd.DataFrame(users),use_container_width=True,hide_index=True)
    normal=[u for u in users if u.get('role')=='user']
    if normal:
        names=[u['username'] for u in normal]
        target=st.selectbox("Select normal user",names)
        action=st.selectbox("Account action",["Block","Unblock","Lock"])
        if st.button("APPLY ACCOUNT ACTION"):
            status={"Block":"blocked","Unblock":"active","Lock":"locked"}[action]
            _db_call('update_user_status',target,status)
            selected=next(u for u in normal if u['username']==target)
            if status!='active': _db_call('revoke_user_sessions',selected['id'])
            _db_call('add_audit_log',_current_user['username'],action.upper(),target,'Account status changed to '+status)
            st.success(f"{target} updated: {status}"); st.rerun()
    else: st.info("No normal user accounts available.")

elif selected_page == "🧾 Audit Logs":
    page_header("SECURITY AUDIT LOGS", "Administrator actions and account activity")
    records=_db_call('get_audit_logs',500)
    if records: st.dataframe(pd.DataFrame(records),use_container_width=True,hide_index=True)
    else: st.info("No audit records yet.")

if selected_page == "🌐 Command Center":

    page_header(
        "COMMAND CENTER",
        "Advanced security intelligence and real-time event analytics"
    )

    left, right = st.columns([1.25, 1])

    with left:

        st.markdown("""
        <div class="hero-card">
            <div class="hero-kicker">NEXUS SECURITY NETWORK</div>
            <div class="hero-heading">
                INTELLIGENCE<br>BEYOND THE THREATS.
            </div>
            <div class="hero-description">
                A centralized security analytics environment for
                monitoring system logs, identifying suspicious events,
                and correlating security incidents.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        with col1:
            metric_card("📡", "TOTAL EVENTS", total_logs)

        with col2:
            metric_card("🛡️", "THREAT ALERTS", total_threats)

        col3, col4 = st.columns(2)

        with col3:
            metric_card("🔗", "INCIDENTS", total_incidents)

        with col4:
            metric_card("🚨", "HIGH SEVERITY", high_threats)

    with right:

        render_3d_globe()

    st.markdown("---")

    panel_title("THREAT INTELLIGENCE OVERVIEW")

    col1, col2 = st.columns([1, 1.3])

    with col1:

        severity_data = pd.DataFrame({
            "Severity": ["HIGH", "MEDIUM", "LOW"],
            "Count": [high_threats, medium_threats, low_threats]
        })

        fig = px.pie(
            severity_data,
            names="Severity",
            values="Count",
            hole=0.72,
            color="Severity",
            color_discrete_map={
                "HIGH": "#ff4560",
                "MEDIUM": "#ffb84d",
                "LOW": "#00d9b2"
            }
        )

        fig.update_traces(
            textinfo="label+value",
            marker=dict(line=dict(color="#0b1321", width=3))
        )

        fig.update_layout(
            annotations=[dict(
                text=f"<b>{total_threats}</b><br>ALERTS",
                x=0.5,
                y=0.5,
                font_size=18,
                showarrow=False,
                font_color="white"
            )]
        )

        st.plotly_chart(
            style_chart(fig, 320),
            use_container_width=True
        )

    with col2:

        event_counts = logs["event_type"].value_counts().reset_index()
        event_counts.columns = ["Event Type", "Count"]

        fig = px.bar(
            event_counts,
            x="Event Type",
            y="Count",
            color="Count",
            color_continuous_scale=["#075985", "#00e5ff", "#8b5cf6"]
        )

        fig.update_layout(coloraxis_showscale=False)

        st.plotly_chart(
            style_chart(fig, 320),
            use_container_width=True
        )

    st.markdown("---")

    panel_title("RECENT SECURITY EVENTS")

    st.dataframe(
        logs.tail(8),
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# SECURITY LOGS
# =========================================================

elif selected_page == "📡 Security Logs":

    page_header(
        "SECURITY LOG ANALYZER",
        "Explore, filter and analyze recorded security events"
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        metric_card("📋", "TOTAL LOG RECORDS", total_logs)

    with col2:
        metric_card(
            "👤",
            "UNIQUE USERS",
            logs["username"].nunique()
        )

    with col3:
        metric_card(
            "🌍",
            "UNIQUE SOURCE IPS",
            logs["source_ip"].nunique()
        )

    st.markdown("---")

    panel_title("FILTER SECURITY EVENTS")

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:

        selected_event = st.selectbox(
            "Event Type",
            ["All"] + sorted(logs["event_type"].astype(str).unique().tolist())
        )

    with filter_col2:

        selected_status = st.selectbox(
            "Event Status",
            ["All"] + sorted(logs["status"].astype(str).unique().tolist())
        )

    filtered_logs = logs.copy()

    if selected_event != "All":
        filtered_logs = filtered_logs[
            filtered_logs["event_type"] == selected_event
        ]

    if selected_status != "All":
        filtered_logs = filtered_logs[
            filtered_logs["status"] == selected_status
        ]

    st.dataframe(
        filtered_logs,
        use_container_width=True,
        hide_index=True
    )

    st.caption(f"Showing {len(filtered_logs)} matching records")

    st.markdown("---")

    panel_title("EVENT DISTRIBUTION")

    event_chart = logs["event_type"].value_counts().reset_index()
    event_chart.columns = ["Event", "Count"]

    fig = px.bar(
        event_chart,
        x="Event",
        y="Count",
        color="Event",
        color_discrete_sequence=[
            "#00e5ff", "#5577ff", "#a855f7", "#00d9b2"
        ]
    )

    st.plotly_chart(
        style_chart(fig, 350),
        use_container_width=True
    )

    csv_data = filtered_logs.to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇ Download Filtered Logs",
        data=csv_data,
        file_name="security_logs.csv",
        mime="text/csv"
    )


# =========================================================
# THREAT INTELLIGENCE
# =========================================================

elif selected_page == "🛡️ Threat Intelligence":

    page_header(
        "THREAT INTELLIGENCE",
        "Rule-based suspicious activity detection and severity analysis"
    )

    c1, c2, c3 = st.columns(3)

    with c1:
        metric_card("🔴", "HIGH", high_threats, "CRITICAL ATTENTION")

    with c2:
        metric_card("🟠", "MEDIUM", medium_threats, "REVIEW REQUIRED")

    with c3:
        metric_card("🟢", "LOW", low_threats, "LOW PRIORITY")

    st.markdown("---")

    panel_title("DETECTED THREAT ALERTS")

    if threats:

        threat_df = pd.DataFrame(threats)

        if "severity" in threat_df.columns:

            threat_df["severity"] = pd.Categorical(
                threat_df["severity"],
                categories=["HIGH", "MEDIUM", "LOW"],
                ordered=True
            )

            threat_df = threat_df.sort_values("severity")

        st.dataframe(
            threat_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.success("No threat alerts found in the current sample.")

    st.markdown("---")

    panel_title("SEVERITY DISTRIBUTION")

    severity_df = pd.DataFrame({
        "Severity": ["HIGH", "MEDIUM", "LOW"],
        "Alerts": [high_threats, medium_threats, low_threats]
    })

    fig = px.bar(
        severity_df,
        x="Severity",
        y="Alerts",
        color="Severity",
        color_discrete_map={
            "HIGH": "#ff4560",
            "MEDIUM": "#ffb84d",
            "LOW": "#00d9b2"
        },
        text="Alerts"
    )

    fig.update_traces(textposition="outside")

    st.plotly_chart(
        style_chart(fig, 350),
        use_container_width=True
    )

    st.info(
        "This academic prototype uses predefined detection rules. "
        "Its alerts are based on the supplied sample security logs."
    )


# =========================================================
# INCIDENT CORRELATION
# =========================================================

elif selected_page == "🔗 Incident Correlation":

    page_header(
        "INCIDENT CORRELATION",
        "Group related security events and identify incident patterns"
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        metric_card("🔗", "TOTAL INCIDENTS", total_incidents)

    with col2:
        metric_card(
            "🚨",
            "HIGH INCIDENTS",
            sum(1 for x in incidents if x["severity"] == "HIGH")
        )

    with col3:
        metric_card(
            "👥",
            "AFFECTED USERS",
            len(set(x["username"] for x in incidents))
        )

    st.markdown("---")

    panel_title("CORRELATED INCIDENT RECORDS")

    if incidents:

        incident_df = pd.DataFrame(incidents)

        st.dataframe(
            incident_df,
            use_container_width=True,
            hide_index=True
        )

        st.markdown("---")

        panel_title("INCIDENT SEVERITY ANALYSIS")

        severity_count = incident_df["severity"].value_counts().reset_index()
        severity_count.columns = ["Severity", "Count"]

        fig = px.bar(
            severity_count,
            x="Severity",
            y="Count",
            color="Severity",
            color_discrete_map={
                "HIGH": "#ff4560",
                "MEDIUM": "#ffb84d",
                "LOW": "#00d9b2"
            }
        )

        st.plotly_chart(
            style_chart(fig, 330),
            use_container_width=True
        )

        panel_title("INCIDENT DETAILS")

        selected_incident = st.selectbox(
            "Select an incident",
            range(len(incidents)),
            format_func=lambda i: (
                f"{incidents[i]['username']} | "
                f"{incidents[i]['incident_type']}"
            )
        )

        incident = incidents[selected_incident]

        st.markdown(f"""
        <div class="glass-card">
            <div class="metric-label">SELECTED INCIDENT</div>
            <div class="metric-value" style="font-size:23px;">
                {incident['incident_type']}
            </div>
            <br>
            <div style="color:#9bb1c8;font-size:13px;">
                Username: {incident['username']}<br><br>
                Source IP: {incident['source_ip']}<br><br>
                Severity: {incident['severity']}<br><br>
                Related Events: {incident['related_events']}<br><br>
                Failed Logins: {incident['failed_logins']}<br><br>
                Successful Logins: {incident['successful_logins']}
            </div>
        </div>
        """, unsafe_allow_html=True)

    else:
        st.info("No correlated incidents found.")


# =========================================================
# DSA LABORATORY
# =========================================================

elif selected_page == "🧬 DSA Laboratory":

    page_header(
        "DSA LABORATORY",
        "Data structures and sorting algorithm performance analysis"
    )

    st.markdown("""
    <div class="hero-card">
        <div class="hero-kicker">ALGORITHM INTELLIGENCE</div>
        <div class="hero-heading">DATA STRUCTURES<br>& ALGORITHMS</div>
        <div class="hero-description">
            Explore the algorithms powering the security analytics system.
            Compare sorting methods and understand their practical role
            in organizing security incidents.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    panel_title("SORTING ALGORITHM COMPARISON")

    sorting_options = [
        "Bubble Sort",
        "Insertion Sort",
        "Merge Sort",
        "Shell Sort",
        "Heap Sort"
    ]

    sorting_method = st.selectbox(
        "Choose sorting algorithm",
        sorting_options
    )

    if st.button("▶ RUN SORTING ALGORITHM"):

        try:

            sorter = SortingAlgorithms()

            method_name = {
                "Bubble Sort": "bubble_sort",
                "Insertion Sort": "insertion_sort",
                "Merge Sort": "merge_sort",
                "Shell Sort": "shell_sort",
                "Heap Sort": "heap_sort"
            }[sorting_method]

            method = getattr(sorter, method_name)

            start_time = time.perf_counter()

            sorted_data = method(incidents.copy())

            end_time = time.perf_counter()

            elapsed = (end_time - start_time) * 1000

            st.success(f"{sorting_method} executed successfully!")

            st.metric(
                "Execution Time",
                f"{elapsed:.6f} ms"
            )

            st.dataframe(
                pd.DataFrame(sorted_data),
                use_container_width=True,
                hide_index=True
            )

        except Exception as error:
            st.error(f"Sorting error: {error}")

    st.markdown("---")

    panel_title("SORTING ALGORITHMS")

    algorithm_info = pd.DataFrame({
        "Algorithm": [
            "Bubble Sort",
            "Insertion Sort",
            "Merge Sort",
            "Shell Sort",
            "Heap Sort"
        ],
        "Average Time Complexity": [
            "O(n²)",
            "O(n²)",
            "O(n log n)",
            "Depends on gap sequence",
            "O(n log n)"
        ],
        "Purpose": [
            "Simple comparison-based sorting",
            "Builds sorted sequence",
            "Divide and conquer",
            "Gap-based sorting",
            "Heap-based priority sorting"
        ]
    })

    st.dataframe(
        algorithm_info,
        use_container_width=True,
        hide_index=True
    )

    st.markdown("---")

    panel_title("DATA STRUCTURE IMPLEMENTATIONS")

    ds_col1, ds_col2 = st.columns(2)

    with ds_col1:
        metric_card("📥", "QUEUE", "FIFO", "FIRST IN FIRST OUT")
        metric_card("📚", "STACK", "LIFO", "LAST IN FIRST OUT")

    with ds_col2:
        metric_card("🔗", "SINGLY LINKED LIST", "SLL")
        metric_card("↔️", "DOUBLY LINKED LIST", "DLL")


# =========================================================
# DATABASE EXPLORER
# =========================================================

elif selected_page == "💾 Database Explorer":

    page_header(
        "DATABASE EXPLORER",
        "SQLite storage and persistent security analytics records"
    )

    col1, col2 = st.columns(2)

    with col1:
        metric_card("📡", "AVAILABLE LOGS", total_logs)

    with col2:
        metric_card("🔗", "AVAILABLE INCIDENTS", total_incidents)

    st.markdown("---")

    panel_title("DATABASE OPERATIONS")

    if st.button("💾 SAVE CURRENT DATA TO DATABASE"):

        try:

            db = DatabaseManager()

            db.save_logs(logs.to_dict("records"))
            db.save_incidents(incidents)

            db.close()

            st.success("Security logs and incidents saved successfully!")

        except Exception as error:
            st.error(f"Database operation failed: {error}")

    st.markdown("---")

    panel_title("DATABASE INFORMATION")

    st.markdown("""
    <div class="glass-card">
        <div class="metric-label">DATABASE ENGINE</div>
        <div class="metric-value" style="font-size:24px;">SQLite</div>
        <br>
        <div style="font-size:12px;color:#9bb1c8;">
            Storage Type: Local Database<br><br>
            Database File: database/cyber_threats.db<br><br>
            Table 1: security_logs<br><br>
            Table 2: incidents
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    panel_title("DATABASE EXPORT")

    st.download_button(
        "⬇ Export Security Logs",
        data=logs.to_csv(index=False).encode("utf-8"),
        file_name="nexus_security_logs.csv",
        mime="text/csv"
    )

    st.download_button(
        "⬇ Export Incident Records",
        data=pd.DataFrame(incidents).to_csv(index=False).encode("utf-8"),
        file_name="nexus_incidents.csv",
        mime="text/csv"
    )


# =========================================================
# FOOTER
# =========================================================

st.markdown("---")

st.markdown("""
<div style="
    text-align:center;
    padding:20px;
    color:#71869f;
    font-size:10px;
    letter-spacing:2px;
">
    NEXUS CYBER INTELLIGENCE SYSTEM
    <br><br>
    SMART CYBER THREAT DETECTION & INCIDENT CORRELATION
    <br><br>
    ACADEMIC PROJECT • 2026
</div>
""", unsafe_allow_html=True)
