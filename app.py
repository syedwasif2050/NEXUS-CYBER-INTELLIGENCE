import streamlit as st
import pandas as pd
import plotly.express as px
import time
from pathlib import Path
from datetime import datetime

from modules.log_processor import LogProcessor
from modules.threat_detector import ThreatDetector
from modules.incident_correlator import IncidentCorrelator
from modules.sorting_algorithms import SortingAlgorithms
from modules.database_manager import DatabaseManager
from modules.authentication import AuthenticationService


# =========================================================
# CONFIG
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
# DESIGN SYSTEM
# =========================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Orbitron:wght@500;700&display=swap');

.stApp {
    background:
    radial-gradient(ellipse at 0% 0%, rgba(0,200,220,.08), transparent 35%),
    radial-gradient(ellipse at 100% 0%, rgba(100,80,255,.09), transparent 40%),
    #080d17;
    color:#edf4ff;
    font-family:Inter,sans-serif;
}

#MainMenu, footer {visibility:hidden;}
header[data-testid="stHeader"] {background:transparent;}

.block-container {
    max-width:1500px;
    padding-top:2rem;
    padding-bottom:3rem;
}

section[data-testid="stSidebar"] {
    background:linear-gradient(180deg,#0e1727,#080d17);
    border-right:1px solid rgba(0,220,255,.15);
}

.nexus-logo {
    font-family:Orbitron,sans-serif;
    font-size:30px;
    font-weight:800;
    letter-spacing:5px;
    color:#00e5ff;
    text-shadow:0 0 20px rgba(0,229,255,.4);
}

.nexus-sub {
    font-size:10px;
    color:#8293aa;
    letter-spacing:3px;
}

.page-title {
    font-family:Orbitron,sans-serif;
    font-size:clamp(25px,3vw,38px);
    font-weight:700;
    color:#eafaff;
}

.page-subtitle {
    color:#8495aa;
    font-size:13px;
    margin-bottom:24px;
}

.section-title {
    font-family:Orbitron,sans-serif;
    color:#dffaff;
    letter-spacing:1px;
    font-size:15px;
    margin-bottom:15px;
}

.glass-card {
    background:linear-gradient(145deg,#142136,#0b1321);
    border:1px solid rgba(0,220,255,.16);
    border-radius:18px;
    padding:22px;
    box-shadow:0 12px 35px rgba(0,0,0,.2);
    transition:.25s;
}

.glass-card:hover {
    border-color:rgba(0,220,255,.45);
    transform:translateY(-3px);
}

.metric-label {
    color:#899db5;
    font-size:11px;
    letter-spacing:1.5px;
}

.metric-value {
    font-family:Orbitron,sans-serif;
    color:#f2fbff;
    font-size:30px;
    font-weight:700;
    margin-top:8px;
    overflow-wrap:anywhere;
}

.metric-foot {
    color:#00d9b2;
    font-size:11px;
    margin-top:7px;
}

.hero-card {
    border:1px solid rgba(0,220,255,.2);
    border-radius:22px;
    padding:28px;
    background:
    radial-gradient(circle at 80% 0%,rgba(0,220,255,.14),transparent 35%),
    linear-gradient(120deg,#112039,#0c1427);
}

.hero-kicker {
    color:#00e5ff;
    font-size:10px;
    letter-spacing:3px;
}

.hero-heading {
    font-family:Orbitron,sans-serif;
    font-size:30px;
    font-weight:700;
    margin:12px 0;
}

.hero-description {
    color:#a2b5ca;
    font-size:13px;
    line-height:1.8;
}

.stButton button {
    border-radius:10px;
    background:linear-gradient(100deg,#087fbd,#515cdd);
    color:white;
    border:1px solid rgba(0,220,255,.2);
    transition:.2s;
}

.stButton button:hover {
    border-color:#00e5ff;
    transform:translateY(-2px);
}

.stTextInput input,
.stSelectbox div[data-baseweb="select"] {
    background:#101b2b;
    color:white;
}

[data-testid="stDataFrame"] {
    border:1px solid rgba(0,220,255,.15);
    border-radius:12px;
}

hr {
    border-color:rgba(0,220,255,.12);
}

@media(max-width:768px) {
    .metric-value {font-size:23px;}
    .hero-heading {font-size:23px;}
    .block-container {padding-top:1rem;}
}
</style>
""", unsafe_allow_html=True)


# =========================================================
# DATABASE HELPERS
# =========================================================

def _db_call(method, *args):
    db = DatabaseManager()
    try:
        return getattr(db, method)(*args)
    finally:
        db.close()


def client_ip():
    try:
        return str(st.context.ip_address or "Unknown")
    except Exception:
        return "Unknown"


def client_device():
    try:
        return str(st.context.headers.get("User-Agent", "Browser"))[:220]
    except Exception:
        return "Browser"


def bootstrap_admin():
    try:
        cfg = st.secrets.get("admin", {})
    except Exception:
        return

    username = cfg.get("username", "")
    password = cfg.get("password", "")

    if username and password:
        service = AuthenticationService()
        try:
            service.create_admin(username, password)
        except Exception as error:
            st.error(f"Admin setup error: {error}")
        finally:
            service.close()


# =========================================================
# AUTHENTICATION
# =========================================================

def render_login():
    st.markdown("<br><br>", unsafe_allow_html=True)

    left, center, right = st.columns([1, 2, 1])

    with left:
        st.markdown("""
        <div class="glass-card">
        <div class="metric-label">NEXUS ACCESS</div>
        <h3>SECURE GATEWAY</h3>
        <p>Identity verification</p>
        <p>Security analytics</p>
        <p>Incident intelligence</p>
        <p>Access monitoring</p>
        </div>
        """, unsafe_allow_html=True)

    with center:
        st.markdown("""
        <div style="text-align:center">
        <div class="nexus-logo">NEXUS</div>
        <div class="page-subtitle">
        SMART CYBER THREAT DETECTION SYSTEM
        </div>
        </div>
        """, unsafe_allow_html=True)

        mode = st.radio(
            "PORTAL",
            ["Login", "Create Account"],
            horizontal=True
        )

        if mode == "Login":

            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input(
                    "Password",
                    type="password"
                )
                submit = st.form_submit_button(
                    "SECURE LOGIN",
                    use_container_width=True
                )

            if submit:
                service = AuthenticationService()

                try:
                    result = service.login(
                        username,
                        password,
                        client_ip(),
                        client_device()
                    )
                except Exception as error:
                    st.error(f"Login error: {error}")
                    result = {"success": False}
                finally:
                    service.close()

                if result.get("success"):
                    st.session_state["nexus_token"] = result["token"]
                    st.rerun()
                else:
                    st.error(result.get("message", "Login failed."))

        else:

            with st.form("register_form"):
                username = st.text_input("Username")
                email = st.text_input("Email (optional)")
                password = st.text_input(
                    "Password",
                    type="password"
                )
                confirm = st.text_input(
                    "Confirm password",
                    type="password"
                )

                submit = st.form_submit_button(
                    "CREATE ACCOUNT",
                    use_container_width=True
                )

            if submit:

                if not username.strip():
                    st.error("Username is required.")

                elif not password:
                    st.error("Password is required.")

                elif password != confirm:
                    st.error("Passwords do not match.")

                else:
                    service = AuthenticationService()

                    try:
                        service.register_user(
                            username.strip(),
                            email,
                            password,
                            client_ip()
                        )
                        st.success("Account created. Please log in.")

                    except Exception as error:
                        st.error(str(error))

                    finally:
                        service.close()

    with right:
        st.markdown("""
        <div class="glass-card">
        <div class="metric-label">SYSTEM STATUS</div>
        <h3 style="color:#00d9b2">ONLINE</h3>
        <p>Access control</p>
        <p>Security logging</p>
        <p>Analytics workspace</p>
        </div>
        """, unsafe_allow_html=True)

    st.stop()


def get_current_user():
    token = st.session_state.get("nexus_token")

    if not token:
        return None

    service = AuthenticationService()

    try:
        return service.verify_session(token)
    finally:
        service.close()


def logout():
    token = st.session_state.pop("nexus_token", None)

    if token:
        service = AuthenticationService()
        try:
            service.logout(token)
        finally:
            service.close()

    st.rerun()


# =========================================================
# DATA LOADING
# =========================================================

@st.cache_data(ttl=60)
def load_project_data():

    if not CSV_PATH.exists():
        return None, [], [], [], "CSV file not found."

    try:
        processor = LogProcessor()
        loaded_logs = processor.load_logs(str(CSV_PATH))

        if loaded_logs is None:
            return None, [], [], [], "Unable to load CSV."

        processed_events = processor.process_logs()

        detector = ThreatDetector()
        detected_threats = detector.detect_threats(processed_events)

        correlator = IncidentCorrelator()
        correlated_incidents = correlator.correlate_events(
            processed_events
        )

        return (
            loaded_logs,
            processed_events,
            detected_threats,
            correlated_incidents,
            None
        )

    except Exception as error:
        return None, [], [], [], str(error)


# =========================================================
# UI HELPERS
# =========================================================

def page_header(title, subtitle):
    st.markdown(
        f"""
        <div class="page-title">{title}</div>
        <div class="page-subtitle">{subtitle}</div>
        """,
        unsafe_allow_html=True
    )


def panel_title(title):
    st.markdown(
        f'<div class="section-title">{title}</div>',
        unsafe_allow_html=True
    )


def metric_card(icon, label, value, foot="SYSTEM ANALYTICS"):
    st.markdown(
        f"""
        <div class="glass-card">
        <div style="font-size:24px">{icon}</div>
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-foot">{foot}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def style_chart(fig, height=350):

    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c7d9ec", family="Inter"),
        margin=dict(l=10, r=10, t=35, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        xaxis=dict(gridcolor="rgba(130,160,190,.10)"),
        yaxis=dict(gridcolor="rgba(130,160,190,.10)")
    )

    return fig


def render_globe():

    components_html = """
    <div id="nx" style="height:330px;background:radial-gradient(circle at center,#123044,#08111d);border:1px solid #164252;border-radius:20px;overflow:hidden;">
    <canvas id="c" style="width:100%;height:100%"></canvas>
    </div>
    <script>
    const box=document.getElementById('nx');
    const c=document.getElementById('c');
    const x=c.getContext('2d');
    let w,h,t=0;
    function size(){
        w=box.clientWidth;
        h=box.clientHeight;
        c.width=w*devicePixelRatio;
        c.height=h*devicePixelRatio;
        x.setTransform(devicePixelRatio,0,0,devicePixelRatio,0,0);
    }
    function draw(){
        t+=0.015;
        x.clearRect(0,0,w,h);
        for(let r=0;r<22;r++){
            x.beginPath();
            for(let q=0;q<60;q++){
                let px=q/59*w;
                let py=h*.25+r*6+
                Math.sin(q*.18+t+r*.2)*12+
                Math.cos(q*.1-t)*8;
                if(q===0)x.moveTo(px,py);
                else x.lineTo(px,py);
            }
            x.strokeStyle='rgba(0,220,190,.23)';
            x.stroke();
        }
        requestAnimationFrame(draw);
    }
    size();draw();
    new ResizeObserver(size).observe(box);
    </script>
    """

    import streamlit.components.v1 as components
    components.html(components_html, height=340)


# =========================================================
# BOOT
# =========================================================

bootstrap_admin()

_current_user = get_current_user()

if not _current_user:
    st.session_state.pop("nexus_token", None)
    render_login()


# =========================================================
# LOAD DATA
# =========================================================

logs, events, threats, incidents, load_error = load_project_data()

if load_error:
    st.error(load_error)
    st.stop()


total_logs = len(logs)
total_threats = len(threats)
total_incidents = len(incidents)

high_threats = sum(
    1 for t in threats
    if str(t.get("severity", "")).upper() == "HIGH"
)

medium_threats = sum(
    1 for t in threats
    if str(t.get("severity", "")).upper() == "MEDIUM"
)

low_threats = sum(
    1 for t in threats
    if str(t.get("severity", "")).upper() == "LOW"
)


# =========================================================
# NAVIGATION
# =========================================================

with st.sidebar:

    st.markdown("""
    <div style="padding:10px 0 20px">
    <div class="nexus-logo">NEXUS</div>
    <div class="nexus-sub">CYBER INTELLIGENCE</div>
    </div>
    """, unsafe_allow_html=True)

    st.caption("SIGNED IN AS")
    st.write(f"**{_current_user['username']}**")
    st.caption(str(_current_user["role"]).upper())

    if _current_user["role"] == "admin":

        pages = [
            "🌐 Command Center",
            "📡 Security Logs",
            "🛡️ Threat Intelligence",
            "🔗 Incident Correlation",
            "🧬 DSA Laboratory",
            "💾 Database Explorer",
            "📟 Live Login Monitor",
            "👥 User Management",
            "🧾 Audit Logs",
            "👤 My Account"
        ]

    else:
        pages = ["👤 My Account"]

    selected_page = st.radio(
        "Navigation",
        pages,
        label_visibility="collapsed"
    )

    st.divider()

    if st.button("LOG OUT", use_container_width=True):
        logout()


# =========================================================
# COMMAND CENTER
# =========================================================

if selected_page == "🌐 Command Center":

    page_header(
        "COMMAND CENTER",
        "Security analytics and threat monitoring"
    )

    left, right = st.columns([1.2, 1])

    with left:

        st.markdown("""
        <div class="hero-card">
        <div class="hero-kicker">NEXUS SECURITY NETWORK</div>
        <div class="hero-heading">INTELLIGENCE<br>BEYOND THREATS</div>
        <div class="hero-description">
        A centralized security environment for analyzing
        logs, identifying suspicious events and
        correlating security incidents.
        </div>
        </div>
        """, unsafe_allow_html=True)

        st.write("")

        a, b = st.columns(2)
        c, d = st.columns(2)

        with a:
            metric_card("📡", "TOTAL LOGS", total_logs)

        with b:
            metric_card("🛡️", "THREAT ALERTS", total_threats)

        with c:
            metric_card("🔗", "INCIDENTS", total_incidents)

        with d:
            metric_card("🚨", "HIGH THREATS", high_threats)

    with right:
        render_globe()

    st.divider()

    panel_title("THREAT ANALYTICS")

    col1, col2 = st.columns(2)

    with col1:

        severity_df = pd.DataFrame({
            "Severity": ["HIGH", "MEDIUM", "LOW"],
            "Count": [
                high_threats,
                medium_threats,
                low_threats
            ]
        })

        fig = px.pie(
            severity_df,
            names="Severity",
            values="Count",
            hole=.65,
            color="Severity",
            color_discrete_map={
                "HIGH": "#ff4560",
                "MEDIUM": "#ffb84d",
                "LOW": "#00d9b2"
            }
        )

        st.plotly_chart(
            style_chart(fig, 320),
            use_container_width=True
        )

    with col2:

        event_counts = logs["event_type"].value_counts().reset_index()
        event_counts.columns = ["Event", "Count"]

        fig = px.bar(
            event_counts,
            x="Event",
            y="Count",
            color="Event"
        )

        st.plotly_chart(
            style_chart(fig, 320),
            use_container_width=True
        )

    panel_title("RECENT EVENTS")

    st.dataframe(
        logs.tail(10),
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# SECURITY LOGS
# =========================================================

elif selected_page == "📡 Security Logs":

    page_header(
        "SECURITY LOG ANALYZER",
        "Filter, search and review recorded events"
    )

    a, b, c = st.columns(3)

    a.metric("TOTAL LOGS", total_logs)
    b.metric("UNIQUE USERS", logs["username"].nunique())
    c.metric("SOURCE IPS", logs["source_ip"].nunique())

    st.divider()

    panel_title("FILTER LOGS")

    col1, col2, col3 = st.columns(3)

    with col1:
        event_type = st.selectbox(
            "Event Type",
            ["All"] + sorted(
                logs["event_type"].astype(str).unique()
            )
        )

    with col2:
        status = st.selectbox(
            "Status",
            ["All"] + sorted(
                logs["status"].astype(str).unique()
            )
        )

    with col3:
        search = st.text_input("Search records")

    filtered = logs.copy()

    if event_type != "All":
        filtered = filtered[
            filtered["event_type"] == event_type
        ]

    if status != "All":
        filtered = filtered[
            filtered["status"] == status
        ]

    if search.strip():

        mask = filtered.astype(str).apply(
            lambda row: row.str.contains(
                search,
                case=False,
                na=False
            ).any(),
            axis=1
        )

        filtered = filtered[mask]

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True
    )

    st.caption(f"{len(filtered)} records")

    st.download_button(
        "DOWNLOAD FILTERED LOGS",
        filtered.to_csv(index=False).encode("utf-8"),
        "security_logs.csv",
        "text/csv"
    )

    panel_title("EVENT DISTRIBUTION")

    chart_data = logs["event_type"].value_counts().reset_index()
    chart_data.columns = ["Event", "Count"]

    fig = px.bar(
        chart_data,
        x="Event",
        y="Count",
        color="Event"
    )

    st.plotly_chart(
        style_chart(fig),
        use_container_width=True
    )


# =========================================================
# THREAT INTELLIGENCE
# =========================================================

elif selected_page == "🛡️ Threat Intelligence":

    page_header(
        "THREAT INTELLIGENCE",
        "Detected suspicious activity and severity analysis"
    )

    a, b, c = st.columns(3)

    a.metric("HIGH", high_threats)
    b.metric("MEDIUM", medium_threats)
    c.metric("LOW", low_threats)

    st.divider()

    panel_title("DETECTED THREATS")

    if threats:

        threat_df = pd.DataFrame(threats)

        if "severity" in threat_df.columns:

            threat_df["severity"] = threat_df[
                "severity"
            ].astype(str)

            threat_df["severity"] = pd.Categorical(
                threat_df["severity"],
                categories=["HIGH", "MEDIUM", "LOW"],
                ordered=True
            )

            threat_df = threat_df.sort_values(
                "severity"
            )

        st.dataframe(
            threat_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No threats found.")

    st.divider()

    severity_df = pd.DataFrame({
        "Severity": ["HIGH", "MEDIUM", "LOW"],
        "Alerts": [
            high_threats,
            medium_threats,
            low_threats
        ]
    })

    fig = px.bar(
        severity_df,
        x="Severity",
        y="Alerts",
        color="Severity",
        text="Alerts"
    )

    st.plotly_chart(
        style_chart(fig),
        use_container_width=True
    )

    st.info(
        "Detection is based on predefined academic "
        "rules and supplied sample logs."
    )


# =========================================================
# INCIDENT CORRELATION
# =========================================================

elif selected_page == "🔗 Incident Correlation":

    page_header(
        "INCIDENT CORRELATION",
        "Analyze correlated events and incident patterns"
    )

    high_incidents = sum(
        1 for i in incidents
        if str(i.get("severity", "")).upper() == "HIGH"
    )

    affected_users = len(set(
        str(i.get("username", "Unknown"))
        for i in incidents
    ))

    a, b, c = st.columns(3)

    a.metric("TOTAL INCIDENTS", total_incidents)
    b.metric("HIGH INCIDENTS", high_incidents)
    c.metric("AFFECTED USERS", affected_users)

    st.divider()

    panel_title("INCIDENT RECORDS")

    if incidents:

        incident_df = pd.DataFrame(incidents)

        st.dataframe(
            incident_df,
            use_container_width=True,
            hide_index=True
        )

        if "severity" in incident_df.columns:

            panel_title("SEVERITY ANALYSIS")

            severity_counts = (
                incident_df["severity"]
                .astype(str)
                .value_counts()
                .reset_index()
            )

            severity_counts.columns = [
                "Severity", "Count"
            ]

            fig = px.bar(
                severity_counts,
                x="Severity",
                y="Count",
                color="Severity"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        panel_title("INCIDENT DETAILS")

        selection = st.selectbox(
            "Select incident",
            range(len(incidents)),
            format_func=lambda i: (
                f"{incidents[i].get('username','Unknown')} | "
                f"{incidents[i].get('incident_type','Incident')} | "
                f"{i+1}"
            )
        )

        item = incidents[selection]

        st.write("**Incident type:**", item.get("incident_type", "N/A"))
        st.write("**Username:**", item.get("username", "N/A"))
        st.write("**Source IP:**", item.get("source_ip", "N/A"))
        st.write("**Severity:**", item.get("severity", "N/A"))
        st.write("**Related events:**", item.get("related_events", "N/A"))
        st.write("**Failed logins:**", item.get("failed_logins", "N/A"))
        st.write("**Successful logins:**", item.get("successful_logins", "N/A"))

    else:
        st.info("No incidents available.")


# =========================================================
# DSA LABORATORY
# =========================================================

elif selected_page == "🧬 DSA Laboratory":

    page_header(
        "DSA LABORATORY",
        "Sorting algorithms and data structure analysis"
    )

    st.markdown("""
    <div class="hero-card">
    <div class="hero-kicker">ALGORITHM INTELLIGENCE</div>
    <div class="hero-heading">DATA STRUCTURES<br>& ALGORITHMS</div>
    <div class="hero-description">
    Explore the algorithms used to organize and
    process security incident data.
    </div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    sorting_options = [
        "Bubble Sort",
        "Insertion Sort",
        "Merge Sort",
        "Shell Sort",
        "Heap Sort"
    ]

    selected_sort = st.selectbox(
        "Sorting algorithm",
        sorting_options
    )

    if st.button("RUN ALGORITHM"):

        try:

            sorter = SortingAlgorithms()

            method_map = {
                "Bubble Sort": "bubble_sort",
                "Insertion Sort": "insertion_sort",
                "Merge Sort": "merge_sort",
                "Shell Sort": "shell_sort",
                "Heap Sort": "heap_sort"
            }

            method = getattr(
                sorter,
                method_map[selected_sort]
            )

            start = time.perf_counter()

            result = method(incidents.copy())

            elapsed = (
                time.perf_counter() - start
            ) * 1000

            st.success("Algorithm completed.")

            st.metric(
                "EXECUTION TIME",
                f"{elapsed:.6f} ms"
            )

            st.dataframe(
                pd.DataFrame(result),
                use_container_width=True,
                hide_index=True
            )

        except Exception as error:
            st.error(str(error))

    st.divider()

    algorithm_df = pd.DataFrame({
        "Algorithm": [
            "Bubble Sort",
            "Insertion Sort",
            "Merge Sort",
            "Shell Sort",
            "Heap Sort"
        ],
        "Average Complexity": [
            "O(n²)",
            "O(n²)",
            "O(n log n)",
            "Gap dependent",
            "O(n log n)"
        ]
    })

    st.dataframe(
        algorithm_df,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    a, b = st.columns(2)

    with a:
        metric_card("📥", "QUEUE", "FIFO")
        metric_card("📚", "STACK", "LIFO")

    with b:
        metric_card("🔗", "SINGLY LINKED LIST", "SLL")
        metric_card("↔️", "DOUBLY LINKED LIST", "DLL")


# =========================================================
# DATABASE EXPLORER
# =========================================================

elif selected_page == "💾 Database Explorer":

    page_header(
        "DATABASE EXPLORER",
        "Persistent SQLite storage and export operations"
    )

    a, b = st.columns(2)

    a.metric("AVAILABLE LOGS", total_logs)
    b.metric("AVAILABLE INCIDENTS", total_incidents)

    st.divider()

    if st.button("SAVE DATA TO DATABASE"):

        db = DatabaseManager()

        try:
            db.save_logs(logs.to_dict("records"))
            db.save_incidents(incidents)
            st.success("Data saved successfully.")

        except Exception as error:
            st.error(str(error))

        finally:
            db.close()

    st.divider()

    st.markdown("""
    <div class="glass-card">
    <div class="metric-label">DATABASE ENGINE</div>
    <div class="metric-value">SQLite</div>
    <br>
    <div class="hero-description">
    Local persistent storage<br><br>
    security_logs<br>
    incidents<br>
    users<br>
    sessions<br>
    security_events<br>
    alerts<br>
    audit_logs
    </div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    st.download_button(
        "EXPORT LOGS",
        logs.to_csv(index=False).encode("utf-8"),
        "nexus_security_logs.csv",
        "text/csv"
    )

    st.download_button(
        "EXPORT INCIDENTS",
        pd.DataFrame(incidents).to_csv(
            index=False
        ).encode("utf-8"),
        "nexus_incidents.csv",
        "text/csv"
    )


# =========================================================
# LIVE LOGIN MONITOR
# =========================================================

elif selected_page == "📟 Live Login Monitor":

    page_header(
        "LIVE LOGIN MONITOR",
        "Recorded account activity and active sessions"
    )

    events_db = _db_call(
        "get_security_events",
        500
    )

    sessions = _db_call(
        "get_active_sessions"
    )

    if events_db is None:
        events_db = []

    if sessions is None:
        sessions = []

    successful = sum(
        1 for e in events_db
        if e.get("event_type") == "LOGIN"
        and e.get("status") == "SUCCESS"
    )

    failed = sum(
        1 for e in events_db
        if e.get("event_type") == "LOGIN"
        and e.get("status") == "FAILED"
    )

    a, b, c = st.columns(3)

    a.metric("ACTIVE SESSIONS", len(sessions))
    b.metric("SUCCESSFUL LOGINS", successful)
    c.metric("FAILED LOGINS", failed)

    st.divider()

    panel_title("ACTIVE SESSIONS")

    if sessions:
        st.dataframe(
            pd.DataFrame(sessions),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No active sessions.")

    st.divider()

    panel_title("RECENT ACCOUNT EVENTS")

    if events_db:

        event_df = pd.DataFrame(events_db)

        st.dataframe(
            event_df,
            use_container_width=True,
            hide_index=True
        )

        if "event_type" in event_df.columns:

            counts = event_df[
                "event_type"
            ].astype(str).value_counts().reset_index()

            counts.columns = [
                "Event", "Count"
            ]

            fig = px.bar(
                counts,
                x="Event",
                y="Count",
                color="Event"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

    else:
        st.info("No events recorded.")

    if st.button("REFRESH MONITOR"):
        st.rerun()

    st.caption(
        "Events are recorded by the application. "
        "This page does not track GPS or hidden location."
    )


# =========================================================
# USER MANAGEMENT
# =========================================================

elif selected_page == "👥 User Management":

    page_header(
        "USER MANAGEMENT",
        "Account administration and access control"
    )

    users = _db_call("get_all_users")

    if users:

        user_df = pd.DataFrame(users)

        st.dataframe(
            user_df,
            use_container_width=True,
            hide_index=True
        )

        normal_users = [
            u for u in users
            if u.get("role") == "user"
        ]

        if normal_users:

            names = [
                u["username"]
                for u in normal_users
            ]

            target = st.selectbox(
                "Select account",
                names
            )

            action = st.selectbox(
                "Account action",
                ["Block", "Unblock", "Lock"]
            )

            if st.button("APPLY ACTION"):

                status_map = {
                    "Block": "blocked",
                    "Unblock": "active",
                    "Lock": "locked"
                }

                new_status = status_map[action]

                _db_call(
                    "update_user_status",
                    target,
                    new_status
                )

                selected = next(
                    u for u in normal_users
                    if u["username"] == target
                )

                if new_status != "active":

                    _db_call(
                        "revoke_user_sessions",
                        selected["id"]
                    )

                _db_call(
                    "add_audit_log",
                    _current_user["username"],
                    action.upper(),
                    target,
                    "Account status changed to " + new_status
                )

                st.success("Account updated.")
                st.rerun()

    else:
        st.info("No accounts found.")


# =========================================================
# AUDIT LOGS
# =========================================================

elif selected_page == "🧾 Audit Logs":

    page_header(
        "AUDIT LOGS",
        "Recorded administrator actions"
    )

    records = _db_call(
        "get_audit_logs",
        500
    )

    if records:

        audit_df = pd.DataFrame(records)

        st.dataframe(
            audit_df,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "EXPORT AUDIT LOGS",
            audit_df.to_csv(index=False).encode("utf-8"),
            "nexus_audit_logs.csv",
            "text/csv"
        )

    else:
        st.info("No audit records available.")


# =========================================================
# USER PORTAL
# =========================================================

elif selected_page == "👤 My Account":

    page_header(
        "USER PORTAL",
        "Account information and personal activity"
    )

    st.markdown("""
    <div class="hero-card">
    <div class="hero-kicker">NEXUS ACCOUNT</div>
    <div class="hero-heading">PERSONAL WORKSPACE</div>
    <div class="hero-description">
    Review your account information and recorded activity.
    </div>
    </div>
    """, unsafe_allow_html=True)

    a, b = st.columns(2)

    a.metric(
        "USERNAME",
        _current_user["username"]
    )

    b.metric(
        "ROLE",
        str(_current_user["role"]).upper()
    )

    st.divider()

    panel_title("MY RECENT ACTIVITY")

    all_events = _db_call(
        "get_security_events",
        500
    )

    own_events = [
        e for e in (all_events or [])
        if str(e.get("username", "")).lower()
        == str(_current_user["username"]).lower()
    ]

    if own_events:

        st.dataframe(
            pd.DataFrame(own_events),
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No activity recorded.")


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.markdown("""
<div style="
text-align:center;
padding:20px;
color:#71869f;
font-size:10px;
letter-spacing:2px;
">
NEXUS CYBER INTELLIGENCE SYSTEM<br><br>
SMART CYBER THREAT DETECTION & INCIDENT CORRELATION<br><br>
ACADEMIC PROJECT • 2026
</div>
""", unsafe_allow_html=True)