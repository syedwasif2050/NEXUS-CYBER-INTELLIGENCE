
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

    html = """
    <!DOCTYPE html>
    <html>
    <head>
    <style>
        * {margin:0;padding:0;box-sizing:border-box;}
        body {
            overflow:hidden;
            background:transparent;
            font-family:Arial,sans-serif;
        }
        #scene {
            width:100%;
            height:440px;
            position:relative;
        }
        .globe-label {
            position:absolute;
            left:18px;
            top:18px;
            color:#00e5ff;
            font-size:10px;
            letter-spacing:3px;
            z-index:2;
            text-shadow:0 0 12px #00e5ff;
        }
        .globe-info {
            position:absolute;
            bottom:18px;
            left:18px;
            color:#9ab4ce;
            font-size:10px;
            letter-spacing:2px;
            z-index:2;
        }
        .globe-status {
            position:absolute;
            right:18px;
            top:18px;
            color:#00e5a8;
            font-size:10px;
            letter-spacing:1px;
            z-index:2;
        }
    </style>
    </head>
    <body>
    <div id="scene">
        <div class="globe-label">NEXUS / GLOBAL NETWORK</div>
        <div class="globe-status">● SYSTEM ACTIVE</div>
        <div class="globe-info">3D THREAT INTELLIGENCE VISUALIZATION</div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>

    <script>
    const container = document.getElementById("scene");

    if (typeof THREE !== "undefined") {

        const scene = new THREE.Scene();

        const camera = new THREE.PerspectiveCamera(
            45,
            container.clientWidth / container.clientHeight,
            0.1,
            1000
        );

        camera.position.z = 5.3;

        const renderer = new THREE.WebGLRenderer({
            alpha: true,
            antialias: true
        });

        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.setSize(container.clientWidth, container.clientHeight);
        container.appendChild(renderer.domElement);

        const globeGroup = new THREE.Group();
        scene.add(globeGroup);

        // Main globe
        const geometry = new THREE.SphereGeometry(1.35, 48, 48);

        const material = new THREE.MeshPhongMaterial({
            color: 0x092a49,
            emissive: 0x061a35,
            transparent: true,
            opacity: 0.95,
            shininess: 90,
            wireframe: false
        });

        const globe = new THREE.Mesh(geometry, material);
        globeGroup.add(globe);

        // Wireframe globe
        const wireGeometry = new THREE.SphereGeometry(1.37, 28, 20);
        const wireMaterial = new THREE.MeshBasicMaterial({
            color: 0x00cfff,
            wireframe: true,
            transparent: true,
            opacity: 0.16
        });

        const wire = new THREE.Mesh(wireGeometry, wireMaterial);
        globeGroup.add(wire);

        // Atmospheric glow
        const glowGeometry = new THREE.SphereGeometry(1.48, 40, 40);
        const glowMaterial = new THREE.MeshBasicMaterial({
            color: 0x007bff,
            transparent: true,
            opacity: 0.09,
            side: THREE.BackSide
        });

        const glow = new THREE.Mesh(glowGeometry, glowMaterial);
        globeGroup.add(glow);

        // Lights
        scene.add(new THREE.AmbientLight(0x6688aa, 1.2));

        const pointLight = new THREE.PointLight(0x00dfff, 3, 10);
        pointLight.position.set(3, 3, 4);
        scene.add(pointLight);

        // Random network points
        const points = [];

        for(let i = 0; i < 65; i++) {

            const phi = Math.acos(2 * Math.random() - 1);
            const theta = Math.random() * Math.PI * 2;

            const x = 1.39 * Math.sin(phi) * Math.cos(theta);
            const y = 1.39 * Math.sin(phi) * Math.sin(theta);
            const z = 1.39 * Math.cos(phi);

            points.push(new THREE.Vector3(x,y,z));

            const nodeGeometry = new THREE.SphereGeometry(
                Math.random() > 0.8 ? 0.035 : 0.018,
                8,
                8
            );

            const nodeMaterial = new THREE.MeshBasicMaterial({
                color: Math.random() > 0.8 ? 0x00ffcc : 0x00aaff
            });

            const node = new THREE.Mesh(nodeGeometry,nodeMaterial);
            node.position.set(x,y,z);
            globeGroup.add(node);
        }

        // Connection lines
        for(let i=0; i<points.length; i++) {

            for(let j=i+1; j<points.length; j++) {

                if(points[i].distanceTo(points[j]) < 0.85 && Math.random() > 0.58) {

                    const lineGeometry = new THREE.BufferGeometry().setFromPoints([
                        points[i],
                        points[j]
                    ]);

                    const lineMaterial = new THREE.LineBasicMaterial({
                        color:0x00aaff,
                        transparent:true,
                        opacity:0.22
                    });

                    const line = new THREE.Line(lineGeometry,lineMaterial);
                    globeGroup.add(line);
                }
            }
        }

        // Orbit rings
        const ringMaterial = new THREE.MeshBasicMaterial({
            color:0x00cfff,
            transparent:true,
            opacity:0.38,
            side:THREE.DoubleSide
        });

        const ring1 = new THREE.Mesh(
            new THREE.TorusGeometry(1.85,0.008,8,120),
            ringMaterial
        );

        ring1.rotation.x = 1.2;
        ring1.rotation.y = 0.3;
        globeGroup.add(ring1);

        const ring2 = new THREE.Mesh(
            new THREE.TorusGeometry(1.75,0.006,8,120),
            new THREE.MeshBasicMaterial({
                color:0x8a55ff,
                transparent:true,
                opacity:0.45
            })
        );

        ring2.rotation.x = 0.3;
        ring2.rotation.y = 1.2;
        globeGroup.add(ring2);

        // Floating particles
        const particleGeometry = new THREE.BufferGeometry();
        const particlePositions = [];

        for(let i=0;i<350;i++) {
            particlePositions.push(
                (Math.random()-0.5)*9,
                (Math.random()-0.5)*6,
                (Math.random()-0.5)*4
            );
        }

        particleGeometry.setAttribute(
            'position',
            new THREE.Float32BufferAttribute(particlePositions,3)
        );

        const particleMaterial = new THREE.PointsMaterial({
            color:0x00bfff,
            size:0.018,
            transparent:true,
            opacity:0.6
        });

        const particles = new THREE.Points(
            particleGeometry,
            particleMaterial
        );

        scene.add(particles);

        // Animation
        let mouseX = 0;
        let mouseY = 0;

        container.addEventListener("mousemove", function(event) {
            const rect = container.getBoundingClientRect();
            mouseX = ((event.clientX-rect.left)/rect.width-0.5)*0.5;
            mouseY = ((event.clientY-rect.top)/rect.height-0.5)*0.3;
        });

        function animate() {
            requestAnimationFrame(animate);

            globeGroup.rotation.y += 0.0025;
            globeGroup.rotation.x += (mouseY-globeGroup.rotation.x)*0.008;
            globeGroup.rotation.z += (mouseX-globeGroup.rotation.z)*0.008;

            ring1.rotation.z += 0.002;
            ring2.rotation.x += 0.0015;

            particles.rotation.y += 0.00025;

            renderer.render(scene,camera);
        }

        animate();

        window.addEventListener("resize", function() {
            const width = container.clientWidth;
            const height = container.clientHeight;

            camera.aspect = width/height;
            camera.updateProjectionMatrix();
            renderer.setSize(width,height);
        });

    } else {
        container.innerHTML +=
        '<div style="color:white;padding:100px 20px;text-align:center">3D engine could not load. Check your internet connection.</div>';
    }
    </script>
    </body>
    </html>
    """

    components.html(html, height=450, scrolling=False)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.markdown("""
    <div style="padding:15px 5px 25px 5px;">
        <div class="nexus-logo">NEXUS</div>
        <div class="nexus-sub">CYBER INTELLIGENCE</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(
        '<div style="color:#00e5ff;font-size:10px;letter-spacing:2px;">MAIN NAVIGATION</div>',
        unsafe_allow_html=True
    )

    selected_page = st.radio(
        "Navigation",
        [
            "🌐 Command Center",
            "📡 Security Logs",
            "🛡️ Threat Intelligence",
            "🔗 Incident Correlation",
            "🧬 DSA Laboratory",
            "💾 Database Explorer"
        ],
        label_visibility="collapsed"
    )

    st.markdown("---")

    st.markdown("""
    <div style="
        background:rgba(0,229,255,.06);
        border:1px solid rgba(0,229,255,.17);
        padding:14px;
        border-radius:12px;
    ">
        <div style="font-size:10px;color:#00e5ff;letter-spacing:2px;">
            SYSTEM STATUS
        </div>
        <div style="margin-top:10px;font-size:12px;">
            <span class="status-dot"></span>Operational
        </div>
        <div style="font-size:10px;color:#8293aa;margin-top:8px;">
            Local Security Analytics
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.caption("NEXUS CYBER SECURITY")
    st.caption("Academic Prototype • 2026")


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
