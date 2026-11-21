import streamlit as st
import pandas as pd
import plotly.express as px
import time
from pathlib import Path

from modules.threat_detection_engine import ThreatDetectionEngine
from modules.sorting_algorithms import SortingAlgorithms
from modules.database_manager import DatabaseManager
from modules.authentication import AuthenticationService


# =========================================================
# CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="NEXUS | Cyber Intelligence",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE_DIR = Path(__file__).resolve().parent


# =========================================================
# DESIGN SYSTEM
# =========================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Orbitron:wght@500;700&display=swap');

.stApp {
    background:
        radial-gradient(ellipse at 0% 0%,rgba(0,200,220,.06),transparent 35%),
        radial-gradient(ellipse at 100% 0%,rgba(100,80,255,.06),transparent 40%),
        #080d17;
    color:#edf4ff;
    font-family:Inter,sans-serif;
}

#MainMenu,footer {
    visibility:hidden;
}

header[data-testid="stHeader"] {
    background:transparent;
}

.block-container {
    max-width:1500px;
    padding-top:1.5rem;
    padding-bottom:2rem;
}

section[data-testid="stSidebar"] {
    background:linear-gradient(180deg,#0e1727,#080d17);
    border-right:1px solid rgba(0,220,255,.12);
}

.nexus-logo {
    font-family:Orbitron,sans-serif;
    font-size:30px;
    font-weight:800;
    letter-spacing:5px;
    color:#00e5ff;
}

.nexus-sub {
    font-size:10px;
    color:#8293aa;
    letter-spacing:3px;
}

.page-title {
    font-family:Orbitron,sans-serif;
    font-size:clamp(24px,3vw,36px);
    font-weight:700;
    color:#eafaff;
}

.page-subtitle {
    color:#8495aa;
    font-size:13px;
    margin-bottom:22px;
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
    border:1px solid rgba(0,220,255,.12);
    border-radius:18px;
    padding:22px;
    box-shadow:0 8px 25px rgba(0,0,0,.15);
}

.metric-label {
    color:#899db5;
    font-size:11px;
    letter-spacing:1.5px;
}

.metric-value {
    font-family:Orbitron,sans-serif;
    color:#f2fbff;
    font-size:28px;
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
    border:1px solid rgba(0,220,255,.15);
    border-radius:22px;
    padding:26px;
    background:
        radial-gradient(circle at 80% 0%,rgba(0,220,255,.12),transparent 35%),
        linear-gradient(120deg,#112039,#0c1427);
}

.hero-kicker {
    color:#00e5ff;
    font-size:10px;
    letter-spacing:3px;
}

.hero-heading {
    font-family:Orbitron,sans-serif;
    font-size:28px;
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
    border:1px solid rgba(0,220,255,.15);
    transition:none;
}

.stButton button:hover {
    border-color:rgba(0,220,255,.3);
    transform:none;
}

.stTextInput input,
.stSelectbox div[data-baseweb="select"] {
    background:#101b2b;
    color:white;
}

[data-testid="stDataFrame"] {
    border:1px solid rgba(0,220,255,.12);
    border-radius:12px;
}

hr {
    border-color:rgba(0,220,255,.12);
}

.glass-card:hover {
    transform:none;
    border-color:rgba(0,220,255,.12);
}

@media(max-width:768px) {

    .metric-value {
        font-size:22px;
    }

    .hero-heading {
        font-size:22px;
    }

    .block-container {
        padding-top:1rem;
    }

}

</style>
""", unsafe_allow_html=True)


# =========================================================
# DATABASE HELPERS
# =========================================================

def db_call(method, *args):

    db = DatabaseManager()

    try:
        return getattr(db, method)(*args)

    finally:
        db.close()


def fetch_page_data(page, username=None):

    db = DatabaseManager()

    try:

        events = []
        alerts = []
        incidents = []
        sessions = []
        users = []
        audit = []

        if page in [
            "🌐 Command Center",
            "📡 Security Logs",
            "📟 Live Login Monitor",
            "👤 My Account"
        ]:

            events = db.get_security_events(500)

        if page in [
            "🌐 Command Center",
            "🛡️ Threat Intelligence"
        ]:

            alerts = db.get_alerts(300)

        if page in [
            "🌐 Command Center",
            "🔗 Incident Correlation",
            "🧬 DSA Laboratory"
        ]:

            incidents = db.get_incidents()

        if page in [
            "🌐 Command Center",
            "📟 Live Login Monitor"
        ]:

            sessions = db.get_active_sessions()

        if page in [
            "🌐 Command Center",
            "👥 User Management",
            "💾 Database Explorer"
        ]:

            users = db.get_all_users()

        if page == "🧾 Audit Logs":

            audit = db.get_audit_logs(100)

        if page == "💾 Database Explorer":

            events = db.get_security_events(500)
            alerts = db.get_alerts(300)
            incidents = db.get_incidents()
            sessions = db.get_active_sessions()
            audit = db.get_audit_logs(100)

        return (
            events or [],
            alerts or [],
            incidents or [],
            sessions or [],
            users or [],
            audit or []
        )

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


# =========================================================
# ADMIN INITIALIZATION
# =========================================================

@st.cache_resource
def bootstrap_admin_once():

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

        finally:
            service.close()


bootstrap_admin_once()


# =========================================================
# AUTHENTICATION
# =========================================================

def render_login():

    st.markdown("<br><br>", unsafe_allow_html=True)

    left, center, right = st.columns([1, 2, 1])

    with left:

        st.markdown("""
        <div class='glass-card'>
        <div class='metric-label'>NEXUS ACCESS</div>
        <h3>SECURE GATEWAY</h3>
        <p>Identity verification</p>
        <p>Security analytics</p>
        <p>Incident intelligence</p>
        <p>Access monitoring</p>
        </div>
        """, unsafe_allow_html=True)

    with center:

        st.markdown("""
        <div style='text-align:center'>
        <div class='nexus-logo'>NEXUS</div>
        <div class='page-subtitle'>
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

                    st.error(
                        result.get(
                            "message",
                            "Login failed."
                        )
                    )

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

                        st.success(
                            "Account created. Please log in."
                        )

                    except Exception as error:

                        st.error(str(error))

                    finally:
                        service.close()

    with right:

        st.markdown("""
        <div class='glass-card'>
        <div class='metric-label'>SYSTEM STATUS</div>
        <h3 style='color:#00d9b2'>ONLINE</h3>
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


_current_user = get_current_user()

if not _current_user:

    st.session_state.pop("nexus_token", None)

    render_login()


# =========================================================
# UI HELPERS
# =========================================================

def page_header(title, subtitle):

    st.markdown(
        f"""
        <div class='page-title'>{title}</div>
        <div class='page-subtitle'>{subtitle}</div>
        """,
        unsafe_allow_html=True
    )


def panel_title(title):

    st.markdown(
        f"<div class='section-title'>{title}</div>",
        unsafe_allow_html=True
    )


def metric_card(icon, label, value, foot="LIVE DATABASE"):

    st.markdown(
        f"""
        <div class='glass-card'>
        <div style='font-size:24px'>{icon}</div>
        <div class='metric-label'>{label}</div>
        <div class='metric-value'>{value}</div>
        <div class='metric-foot'>{foot}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def style_chart(fig, height=350):

    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            color="#c7d9ec",
            family="Inter"
        ),
        margin=dict(
            l=10,
            r=10,
            t=35,
            b=10
        ),
        legend=dict(
            bgcolor="rgba(0,0,0,0)"
        ),
        xaxis=dict(
            gridcolor="rgba(130,160,190,.10)"
        ),
        yaxis=dict(
            gridcolor="rgba(130,160,190,.10)"
        )
    )

    return fig


def to_df(records):

    return pd.DataFrame(records or [])


def empty_info(df, message="No records found."):

    if df.empty:
        st.info(message)


def severity_counts(alert_df):

    if alert_df.empty or "severity" not in alert_df:

        return {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

    s = alert_df["severity"].astype(str).str.upper().value_counts()

    return {
        key: int(s.get(key, 0))
        for key in ["HIGH", "MEDIUM", "LOW"]
    }


# =========================================================
# GLOBE
# =========================================================

def render_globe():

    import streamlit.components.v1 as components

    html = """
    <div id='nx' style='height:320px;
    background:radial-gradient(circle at center,#123044,#08111d);
    border:1px solid #164252;border-radius:20px;overflow:hidden'>
    <canvas id='c' style='width:100%;height:100%'></canvas>
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

        x.setTransform(
            devicePixelRatio,
            0,
            0,
            devicePixelRatio,
            0,
            0
        );

    }

    function draw(){

        t+=.015;
        x.clearRect(0,0,w,h);

        for(let r=0;r<22;r++){

            x.beginPath();

            for(let q=0;q<60;q++){

                let px=q/59*w;

                let py=h*.25+r*6+
                Math.sin(q*.18+t+r*.2)*12+
                Math.cos(q*.1-t)*8;

                if(q===0)
                    x.moveTo(px,py);
                else
                    x.lineTo(px,py);

            }

            x.strokeStyle='rgba(0,220,190,.23)';
            x.stroke();

        }

        requestAnimationFrame(draw);

    }

    size();
    draw();

    new ResizeObserver(size).observe(box);

    </script>
    """

    components.html(html, height=330)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.markdown("""
    <div style='padding:10px 0 20px'>
    <div class='nexus-logo'>NEXUS</div>
    <div class='nexus-sub'>CYBER INTELLIGENCE</div>
    </div>
    """, unsafe_allow_html=True)

    st.caption("SIGNED IN AS")
    st.write(f"**{_current_user['username']}**")
    st.caption(str(_current_user["role"]).upper())

    admin_pages = [
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

    pages = (
        admin_pages
        if _current_user["role"] == "admin"
        else ["👤 My Account"]
    )

    selected_page = st.radio(
        "Navigation",
        pages,
        label_visibility="collapsed"
    )

    st.divider()

    if st.button("LOG OUT", use_container_width=True):
        logout()


# =========================================================
# LIVE PAGES
# =========================================================

@st.fragment(run_every="15s")
def render_live_page(page):

    (
        events,
        alerts,
        incidents,
        sessions,
        users,
        audit
    ) = fetch_page_data(page, _current_user["username"])

    event_df = to_df(events)
    alert_df = to_df(alerts)
    incident_df = to_df(incidents)
    session_df = to_df(sessions)
    user_df = to_df(users)
    audit_df = to_df(audit)

    sev = severity_counts(alert_df)

    total_events = len(event_df)
    total_alerts = len(alert_df)
    total_incidents = len(incident_df)

    # =====================================================
    # COMMAND CENTER
    # =====================================================

    if page == "🌐 Command Center":

        page_header(
            "COMMAND CENTER",
            "Live security analytics and account activity"
        )

        left, right = st.columns([1.2, 1])

        with left:

            st.markdown("""
            <div class='hero-card'>
            <div class='hero-kicker'>NEXUS SECURITY NETWORK</div>
            <div class='hero-heading'>
            INTELLIGENCE<br>BEYOND THREATS
            </div>
            <div class='hero-description'>
            A centralized security environment for real
            application events, alert monitoring and incident review.
            </div>
            </div>
            """, unsafe_allow_html=True)

            st.write("")

            a, b = st.columns(2)
            c, d = st.columns(2)

            with a:
                metric_card("📡", "TOTAL EVENTS", total_events)

            with b:
                metric_card("🛡️", "THREAT ALERTS", total_alerts)

            with c:
                metric_card("🔗", "INCIDENTS", total_incidents)

            with d:
                metric_card("🚨", "HIGH ALERTS", sev["HIGH"])

        with right:

            render_globe()

        st.divider()

        panel_title("THREAT ANALYTICS")

        col1, col2 = st.columns(2)

        with col1:

            sdf = pd.DataFrame({
                "Severity": ["HIGH", "MEDIUM", "LOW"],
                "Count": [
                    sev["HIGH"],
                    sev["MEDIUM"],
                    sev["LOW"]
                ]
            })

            fig = px.pie(
                sdf,
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

            if not event_df.empty and "event_type" in event_df:

                counts = (
                    event_df["event_type"]
                    .astype(str)
                    .value_counts()
                    .reset_index()
                )

                counts.columns = ["Event", "Count"]

                fig = px.bar(
                    counts,
                    x="Event",
                    y="Count",
                    color="Event"
                )

                st.plotly_chart(
                    style_chart(fig, 320),
                    use_container_width=True
                )

            else:

                st.info("No event records yet.")

        panel_title("RECENT EVENTS")

        empty_info(
            event_df,
            "No application events have been recorded."
        )

        if not event_df.empty:

            st.dataframe(
                event_df.head(10),
                use_container_width=True,
                hide_index=True
            )

        panel_title("OPEN ALERTS")

        open_alerts = (
            alert_df[
                alert_df["status"].astype(str).str.lower() == "open"
            ]
            if not alert_df.empty and "status" in alert_df
            else pd.DataFrame()
        )

        empty_info(open_alerts, "No open alerts.")

        if not open_alerts.empty:

            st.dataframe(
                open_alerts.head(10),
                use_container_width=True,
                hide_index=True
            )


    # =====================================================
    # SECURITY LOGS
    # =====================================================

    elif page == "📡 Security Logs":

        page_header(
            "SECURITY LOG ANALYZER",
            "Filter and review actual application events"
        )

        a, b, c = st.columns(3)

        a.metric("TOTAL EVENTS", total_events)

        b.metric(
            "UNIQUE USERS",
            event_df.username.nunique()
            if not event_df.empty and "username" in event_df
            else 0
        )

        c.metric(
            "SOURCE IPS",
            event_df.source_ip.nunique()
            if not event_df.empty and "source_ip" in event_df
            else 0
        )

        st.divider()

        panel_title("FILTER EVENTS")

        if event_df.empty:

            st.info("No events recorded yet.")

        else:

            x, y, z = st.columns(3)

            with x:

                et = (
                    st.selectbox(
                        "Event Type",
                        ["All"] + sorted(
                            event_df.event_type.astype(str).unique()
                        ),
                        key="live_event_type"
                    )
                    if "event_type" in event_df
                    else "All"
                )

            with y:

                stat = (
                    st.selectbox(
                        "Status",
                        ["All"] + sorted(
                            event_df.status.astype(str).unique()
                        ),
                        key="live_status"
                    )
                    if "status" in event_df
                    else "All"
                )

            with z:

                search = st.text_input(
                    "Search records",
                    key="live_search"
                )

            filtered = event_df.copy()

            if et != "All" and "event_type" in filtered:

                filtered = filtered[
                    filtered.event_type.astype(str) == et
                ]

            if stat != "All" and "status" in filtered:

                filtered = filtered[
                    filtered.status.astype(str) == stat
                ]

            if search.strip():

                filtered = filtered[
                    filtered.astype(str).apply(
                        lambda row: row.str.contains(
                            search,
                            case=False,
                            na=False
                        ).any(),
                        axis=1
                    )
                ]

            st.dataframe(
                filtered,
                use_container_width=True,
                hide_index=True
            )

            st.caption(f"{len(filtered)} records")

            st.download_button(
                "DOWNLOAD FILTERED EVENTS",
                filtered.to_csv(index=False).encode("utf-8"),
                "nexus_security_events.csv",
                "text/csv",
                key="event_download"
            )

            if "event_type" in event_df:

                counts = (
                    event_df.event_type.astype(str)
                    .value_counts()
                    .reset_index()
                )

                counts.columns = ["Event", "Count"]

                fig = px.bar(
                    counts,
                    x="Event",
                    y="Count",
                    color="Event"
                )

                panel_title("EVENT DISTRIBUTION")

                st.plotly_chart(
                    style_chart(fig),
                    use_container_width=True
                )


    # =====================================================
    # THREAT INTELLIGENCE
    # =====================================================

    elif page == "🛡️ Threat Intelligence":

        page_header(
            "THREAT INTELLIGENCE",
            "Database-backed alert review"
        )

        a, b, c = st.columns(3)

        a.metric("HIGH", sev["HIGH"])
        b.metric("MEDIUM", sev["MEDIUM"])
        c.metric("LOW", sev["LOW"])

        st.divider()

        panel_title("RECORDED ALERTS")

        empty_info(alert_df, "No alerts generated yet.")

        if not alert_df.empty:

            if "severity" in alert_df:

                alert_df = alert_df.sort_values(
                    "severity",
                    key=lambda x: x.astype(str).str.upper().map({
                        "HIGH": 0,
                        "MEDIUM": 1,
                        "LOW": 2
                    }).fillna(3)
                )

            st.dataframe(
                alert_df,
                use_container_width=True,
                hide_index=True
            )

            sdf = pd.DataFrame({
                "Severity": ["HIGH", "MEDIUM", "LOW"],
                "Alerts": [
                    sev["HIGH"],
                    sev["MEDIUM"],
                    sev["LOW"]
                ]
            })

            fig = px.bar(
                sdf,
                x="Severity",
                y="Alerts",
                color="Severity",
                text="Alerts"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        st.caption(
            "Alerts reflect actual records generated by "
            "NEXUS event rules, not CSV sample threats."
        )


    # =====================================================
    # INCIDENT CORRELATION
    # =====================================================

    elif page == "🔗 Incident Correlation":

        page_header(
            "INCIDENT CORRELATION",
            "Actual saved incident records"
        )

        high = sum(
            1 for i in incidents
            if str(i.get("severity", "")).upper() == "HIGH"
        )

        affected = len(
            set(
                str(i.get("username", "Unknown"))
                for i in incidents
            )
        )

        a, b, c = st.columns(3)

        a.metric("TOTAL INCIDENTS", total_incidents)
        b.metric("HIGH INCIDENTS", high)
        c.metric("AFFECTED USERS", affected)

        st.divider()

        panel_title("INCIDENT RECORDS")

        empty_info(
            incident_df,
            "No incidents have been generated."
        )

        if not incident_df.empty:

            st.dataframe(
                incident_df,
                use_container_width=True,
                hide_index=True
            )

            if "severity" in incident_df:

                counts = (
                    incident_df.severity.astype(str)
                    .value_counts()
                    .reset_index()
                )

                counts.columns = ["Severity", "Count"]

                fig = px.bar(
                    counts,
                    x="Severity",
                    y="Count",
                    color="Severity"
                )

                panel_title("SEVERITY ANALYSIS")

                st.plotly_chart(
                    style_chart(fig),
                    use_container_width=True
                )

            if "incident_type" in incident_df:

                choices = list(range(len(incidents)))

                idx = st.selectbox(
                    "Select incident",
                    choices,
                    format_func=lambda i:
                    f"{incidents[i].get('username','Unknown')} | "
                    f"{incidents[i].get('incident_type','Incident')} | "
                    f"record {i+1}",
                    key="incident_select"
                )

                item = incidents[idx]

                for label, key in [
                    ("Incident type", "incident_type"),
                    ("Username", "username"),
                    ("Source IP", "source_ip"),
                    ("Severity", "severity"),
                    ("Related events", "related_events")
                ]:

                    st.write(
                        f"**{label}:**",
                        item.get(key, "N/A")
                    )


    # =====================================================
    # DATABASE EXPLORER
    # =====================================================

    elif page == "💾 Database Explorer":

        page_header(
            "DATABASE EXPLORER",
            "Live PostgreSQL / Supabase records"
        )

        a, b, c, d = st.columns(4)

        a.metric("EVENTS", len(event_df))
        b.metric("ALERTS", len(alert_df))
        c.metric("INCIDENTS", len(incident_df))
        d.metric("USERS", len(user_df))

        st.divider()

        st.markdown("""
        <div class='glass-card'>
        <div class='metric-label'>DATABASE ENGINE</div>
        <div class='metric-value'>PostgreSQL</div>
        <br>
        <div class='hero-description'>
        Supabase PostgreSQL · Persistent application data
        <br><br>
        security_events · alerts · incidents · users ·
        sessions · audit_logs
        </div>
        </div>
        """, unsafe_allow_html=True)

        st.divider()

        panel_title("DATABASE TABLE VIEW")

        table_choice = st.selectbox(
            "Table",
            [
                "Security Events",
                "Alerts",
                "Incidents",
                "Users",
                "Active Sessions",
                "Audit Logs"
            ],
            key="db_table"
        )

        table_map = {
            "Security Events": event_df,
            "Alerts": alert_df,
            "Incidents": incident_df,
            "Users": user_df,
            "Active Sessions": session_df,
            "Audit Logs": audit_df
        }

        selected_df = table_map[table_choice]

        empty_info(
            selected_df,
            "This table currently has no records."
        )

        if not selected_df.empty:

            st.dataframe(
                selected_df,
                use_container_width=True,
                hide_index=True
            )

            st.download_button(
                "EXPORT SELECTED TABLE",
                selected_df.to_csv(index=False).encode("utf-8"),
                f"nexus_{table_choice.lower().replace(' ', '_')}.csv",
                "text/csv",
                key="db_export"
            )


    # =====================================================
    # LIVE LOGIN MONITOR
    # =====================================================

    elif page == "📟 Live Login Monitor":

        page_header(
            "LIVE LOGIN MONITOR",
            "Recorded account activity and current sessions"
        )

        successful = sum(
            1 for e in events
            if e.get("event_type") == "LOGIN"
            and e.get("status") == "SUCCESS"
        )

        failed = sum(
            1 for e in events
            if e.get("event_type") == "LOGIN"
            and e.get("status") == "FAILED"
        )

        a, b, c = st.columns(3)

        a.metric("ACTIVE SESSIONS", len(session_df))
        b.metric("SUCCESSFUL LOGINS", successful)
        c.metric("FAILED LOGINS", failed)

        st.divider()

        panel_title("ACTIVE SESSIONS")

        empty_info(session_df, "No active sessions.")

        if not session_df.empty:

            st.dataframe(
                session_df,
                use_container_width=True,
                hide_index=True
            )

        st.divider()

        panel_title("RECENT ACCOUNT EVENTS")

        empty_info(event_df, "No account events recorded.")

        if not event_df.empty:

            login_events = (
                event_df[
                    event_df.event_type.astype(str).isin(
                        ["LOGIN", "LOGOUT", "REGISTER"]
                    )
                ]
                if "event_type" in event_df
                else event_df
            )

            st.dataframe(
                login_events.head(300),
                use_container_width=True,
                hide_index=True
            )

        st.caption(
            "This monitor refreshes automatically every 15 seconds."
        )


    # =====================================================
    # USER MANAGEMENT
    # =====================================================

    elif page == "👥 User Management":

        page_header(
            "USER MANAGEMENT",
            "Account administration and access control"
        )

        empty_info(user_df, "No accounts found.")

        if not user_df.empty:

            st.dataframe(
                user_df,
                use_container_width=True,
                hide_index=True
            )

            normal = [
                u for u in users
                if u.get("role") == "user"
            ]

            if normal:

                names = [
                    u["username"]
                    for u in normal
                ]

                target = st.selectbox(
                    "Select account",
                    names,
                    key="manage_target"
                )

                action = st.selectbox(
                    "Account action",
                    ["Block", "Unblock", "Lock"],
                    key="manage_action"
                )

                if st.button("APPLY ACTION"):

                    status_map = {
                        "Block": "blocked",
                        "Unblock": "active",
                        "Lock": "locked"
                    }

                    new_status = status_map[action]

                    db_call(
                        "update_user_status",
                        target,
                        new_status
                    )

                    chosen = next(
                        u for u in normal
                        if u["username"] == target
                    )

                    if new_status != "active":

                        db_call(
                            "revoke_user_sessions",
                            chosen["id"]
                        )

                    db_call(
                        "add_audit_log",
                        _current_user["username"],
                        action.upper(),
                        target,
                        "Account status changed to " + new_status
                    )

                    st.success("Account updated.")

                    st.rerun(scope="app")


    # =====================================================
    # AUDIT LOGS
    # =====================================================

    elif page == "🧾 Audit Logs":

        page_header(
            "AUDIT LOGS",
            "Recorded administrative actions"
        )

        empty_info(
            audit_df,
            "No audit records available."
        )

        if not audit_df.empty:

            st.dataframe(
                audit_df,
                use_container_width=True,
                hide_index=True
            )

            st.download_button(
                "EXPORT AUDIT LOGS",
                audit_df.to_csv(index=False).encode("utf-8"),
                "nexus_audit_logs.csv",
                "text/csv",
                key="audit_download"
            )


    # =====================================================
    # MY ACCOUNT
    # =====================================================

    elif page == "👤 My Account":

        page_header(
            "USER PORTAL",
            "Account information and personal activity"
        )

        st.markdown("""
        <div class='hero-card'>
        <div class='hero-kicker'>NEXUS ACCOUNT</div>
        <div class='hero-heading'>PERSONAL WORKSPACE</div>
        <div class='hero-description'>
        Review your account information and recorded activity.
        </div>
        </div>
        """, unsafe_allow_html=True)

        a, b = st.columns(2)

        a.metric("USERNAME", _current_user["username"])
        b.metric("ROLE", str(_current_user["role"]).upper())

        st.divider()

        panel_title("MY RECENT ACTIVITY")

        own = [
            e for e in events
            if str(e.get("username", "")).lower()
            == str(_current_user["username"]).lower()
        ]

        own_df = to_df(own)

        empty_info(own_df, "No activity recorded.")

        if not own_df.empty:

            st.dataframe(
                own_df,
                use_container_width=True,
                hide_index=True
            )


# =========================================================
# DSA LABORATORY
# =========================================================

if selected_page == "🧬 DSA Laboratory":

    page_header(
        "DSA LABORATORY",
        "Sorting algorithms and data structure analysis"
    )

    st.markdown("""
    <div class='hero-card'>
    <div class='hero-kicker'>ALGORITHM INTELLIGENCE</div>
    <div class='hero-heading'>
    DATA STRUCTURES<br>& ALGORITHMS
    </div>
    <div class='hero-description'>
    Explore algorithms to organize and process saved incident records.
    </div>
    </div>
    """, unsafe_allow_html=True)

    try:

        dsa_incidents = db_call("get_incidents") or []

    except Exception as error:

        dsa_incidents = []
        st.error(str(error))

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

            start = time.perf_counter()

            result = getattr(
                sorter,
                method_map[selected_sort]
            )(dsa_incidents.copy())

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

    st.dataframe(
        pd.DataFrame({
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
        }),
        use_container_width=True,
        hide_index=True
    )

    a, b = st.columns(2)

    with a:

        metric_card("📥", "QUEUE", "FIFO")
        metric_card("📚", "STACK", "LIFO")

    with b:

        metric_card("🔗", "SINGLY LINKED LIST", "SLL")
        metric_card("↔️", "DOUBLY LINKED LIST", "DLL")

else:

    render_live_page(selected_page)


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.markdown("""
<div style='text-align:center;padding:20px;color:#71869f;
font-size:10px;letter-spacing:2px;'>
NEXUS CYBER INTELLIGENCE SYSTEM
<br><br>
SMART CYBER THREAT DETECTION & INCIDENT CORRELATION
<br><br>
ACADEMIC PROJECT • 2026
</div>
""", unsafe_allow_html=True)