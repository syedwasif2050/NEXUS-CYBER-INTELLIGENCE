import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone

from modules.authentication import AuthenticationService
from modules.database_manager import DatabaseManager
from modules.data_structures import Queue, Stack, SinglyLinkedList, DoublyLinkedList
from modules.sorting_algorithms import SortingAlgorithms
from modules.incident_correlator import IncidentCorrelator


st.set_page_config(
    page_title="NEXUS | Cyber Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- FUTURISTIC DESIGN SYSTEM ----------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
:root {
 --bg:#050b18; --panel:rgba(10,22,43,.82); --panel2:rgba(13,34,59,.86);
 --line:rgba(67,190,255,.20); --cyan:#56e5ff; --blue:#388cff;
 --muted:#8eabc9; --white:#effaff; --aqua:#1ce0c4;
}
html, body, [class*="css"] {font-family:Inter,sans-serif;}
.stApp {
 color:var(--white);
 background:
  radial-gradient(ellipse at 12% 12%,rgba(0,160,255,.16),transparent 32%),
  radial-gradient(ellipse at 88% 8%,rgba(0,230,205,.12),transparent 30%),
  linear-gradient(145deg,#030916 0%,#07172b 48%,#04101e 100%);
}
[data-testid="stHeader"]{background:rgba(3,9,22,.45);}
[data-testid="stSidebar"]{
 background:linear-gradient(180deg,rgba(5,18,36,.98),rgba(3,10,23,.99));
 border-right:1px solid rgba(65,195,255,.18);
}
[data-testid="stSidebar"]>div{padding-top:1.1rem;}
[data-testid="stMetric"]{
 background:linear-gradient(145deg,rgba(13,43,72,.86),rgba(6,20,39,.92));
 border:1px solid rgba(69,194,255,.24); border-radius:17px;
 padding:17px 18px; box-shadow:0 12px 34px rgba(0,0,0,.22),inset 0 1px rgba(255,255,255,.04);
}
[data-testid="stMetricLabel"]{color:#8eb8d6!important;font-size:.74rem;letter-spacing:.11em;font-weight:700;}
[data-testid="stMetricValue"]{color:#f1fbff!important;font-weight:850;}
.stButton>button,.stFormSubmitButton>button{
 border:1px solid rgba(75,210,255,.38);border-radius:11px;color:#f3fcff;
 font-weight:750;background:linear-gradient(110deg,#075078,#087f89);
 transition:all .22s ease;box-shadow:0 5px 20px rgba(0,170,220,.10);
}
.stButton>button:hover,.stFormSubmitButton>button:hover{
 border-color:#65efff;box-shadow:0 0 22px rgba(48,213,255,.28);transform:translateY(-2px);
}
.stTextInput input,.stSelectbox div[data-baseweb="select"]>div{
 background:rgba(5,20,39,.92)!important;border-color:#245477!important;
 color:#effaff!important;border-radius:10px!important;
}
h1,h2,h3{color:#f1faff;letter-spacing:-.035em;}
p,label,.stMarkdown{color:#d6eaf8;}
.nx-kicker{color:#57dfff;font-size:10px;letter-spacing:3px;font-weight:850;}
.nx-title{font-size:clamp(28px,4vw,43px);font-weight:900;letter-spacing:-2px;color:#f3fbff;margin:0;}
.nx-sub{color:#8eafca;letter-spacing:1.7px;font-size:10px;font-weight:750;}
.nx-panel{
 background:linear-gradient(145deg,rgba(12,39,66,.84),rgba(5,17,34,.92));
 border:1px solid rgba(73,194,255,.22);border-radius:19px;padding:20px 22px;
 box-shadow:0 15px 40px rgba(0,0,0,.24),inset 0 1px rgba(255,255,255,.035);
}
.nx-glow{color:#5ceaff;text-shadow:0 0 22px rgba(56,216,255,.42);}
.nx-pill{display:inline-block;padding:6px 11px;border:1px solid rgba(73,220,255,.32);
 border-radius:30px;color:#9af1ff;background:rgba(17,140,170,.13);
 font-size:9px;letter-spacing:1.5px;font-weight:850;}
div[data-testid="stDataFrame"]{border:1px solid rgba(73,194,255,.20);border-radius:13px;overflow:hidden;}
hr{border-color:rgba(73,194,255,.17);}
footer{visibility:hidden;}
/* Wave-inspired section separators and interactive surfaces */
.stTabs [data-baseweb="tab-list"]{gap:8px;background:rgba(6,23,42,.72);padding:7px;border-radius:13px;}
.stTabs [data-baseweb="tab"]{border-radius:9px;color:#a9c8dc;}
.stTabs [aria-selected="true"]{background:linear-gradient(110deg,#075078,#087f89);color:white;}
[data-testid="stExpander"]{border:1px solid rgba(73,194,255,.2);border-radius:13px;background:rgba(8,27,48,.5);}
</style>
""", unsafe_allow_html=True)


# ---------------- HELPERS ----------------

def get_db():
    return DatabaseManager()


def get_client_info():
    try:
        return str(st.context.headers.get("User-Agent", "Browser session"))[:250]
    except Exception:
        return "Browser session"


def get_client_ip():
    try:
        return st.context.ip_address or "Unknown"
    except Exception:
        return "Unknown"


def load_current_user():
    token = st.session_state.get("nexus_token")
    if not token:
        return None
    auth = AuthenticationService()
    try:
        return auth.verify_session(token)
    finally:
        auth.close()


def logout():
    token = st.session_state.get("nexus_token")
    if token:
        auth = AuthenticationService()
        try:
            auth.logout(token)
        finally:
            auth.close()
    st.session_state.pop("nexus_token", None)
    st.session_state.pop("nexus_user", None)
    st.rerun()


def section_title(title, subtitle=""):
    st.markdown(
        f'<div style="margin:4px 0 22px"><div class="nx-kicker">NEXUS / SECURITY OPERATIONS</div>'
        f'<div class="nx-title">{title}</div><div class="nx-sub">{subtitle}</div></div>',
        unsafe_allow_html=True
    )


def get_events():
    db = get_db()
    try:
        return db.get_security_events(500)
    finally:
        db.close()


def get_alerts():
    db = get_db()
    try:
        return db.get_alerts(limit=500)
    finally:
        db.close()


def get_users():
    db = get_db()
    try:
        return db.get_all_users()
    finally:
        db.close()


def get_sessions():
    db = get_db()
    try:
        return db.get_active_sessions()
    finally:
        db.close()


def get_audit():
    db = get_db()
    try:
        return db.get_audit_logs(500)
    finally:
        db.close()


def animated_globe(height=330):
    """Animated 3D ocean-wave network surface, rendered locally in a canvas."""
    html = """
    <div id="nx-wave-wrap" style="height:HEIGHTpx;width:100%;position:relative;overflow:hidden;
      border:1px solid rgba(74,205,255,.24);border-radius:20px;
      background:radial-gradient(ellipse at 50% 5%,rgba(0,170,220,.18),rgba(3,13,29,.15) 58%,rgba(2,8,20,.45));">
      <canvas id="nx-wave" style="width:100%;height:100%;display:block"></canvas>
      <div style="position:absolute;left:20px;top:17px;font:850 10px Inter,sans-serif;
        letter-spacing:2.2px;color:#6beaff">NEXUS / LIVE NETWORK FIELD</div>
      <div style="position:absolute;right:18px;bottom:14px;font:750 9px Inter,sans-serif;
        letter-spacing:1.5px;color:#77aeca">3D WAVE VISUALIZATION</div>
      <div style="position:absolute;left:20px;bottom:14px;font:700 9px Inter,sans-serif;
        letter-spacing:1.4px;color:#5bd9d2">● SYSTEM VISUALIZATION ACTIVE</div>
    </div>
    <script>
    (() => {
      const canvas=document.getElementById('nx-wave');
      if(!canvas) return;
      const ctx=canvas.getContext('2d');
      let w=0,h=0,t=0,raf=0;
      const resize=()=>{
        const r=canvas.getBoundingClientRect(),d=Math.min(window.devicePixelRatio||1,2);
        w=r.width;h=r.height;canvas.width=w*d;canvas.height=h*d;ctx.setTransform(d,0,0,d,0,0);
      };
      function draw(){
        t+=0.012;ctx.clearRect(0,0,w,h);
        const horizon=h*.23, rows=27, cols=Math.max(42,Math.floor(w/15));
        const points=[];
        for(let r=0;r<rows;r++){
          const row=[];
          const depth=r/(rows-1);
          for(let c=0;c<=cols;c++){
            const x=(c/cols-.5)*w*1.35;
            const wave1=Math.sin(c*.19+t*1.4+r*.22)*15;
            const wave2=Math.cos(c*.085-t*.8+r*.34)*10;
            const wave3=Math.sin(c*.035+t*.55)*8;
            const y=horizon+depth*depth*h*.86+(wave1+wave2+wave3)*(.22+depth*.9);
            const perspective=.24+depth*.95;
            row.push({x:w*.5+x*perspective,y,depth});
          }
          points.push(row);
        }
        // Soft atmospheric glow
        const glow=ctx.createRadialGradient(w*.5,h*.55,2,w*.5,h*.55,w*.62);
        glow.addColorStop(0,'rgba(0,190,225,.13)');glow.addColorStop(1,'rgba(0,20,45,0)');
        ctx.fillStyle=glow;ctx.fillRect(0,0,w,h);
        // Perspective wave mesh
        for(let r=0;r<rows;r++){
          ctx.beginPath();
          for(let c=0;c<=cols;c++){const p=points[r][c];c?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y);}
          ctx.strokeStyle='rgba(42,202,242,'+(0.10+points[r][0].depth*.23)+')';
          ctx.lineWidth=.7;ctx.stroke();
        }
        for(let c=0;c<=cols;c+=2){
          ctx.beginPath();
          for(let r=0;r<rows;r++){const p=points[r][c];r?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y);}
          ctx.strokeStyle='rgba(55,180,235,.16)';ctx.lineWidth=.65;ctx.stroke();
        }
        // Moving signal points across the wave field
        for(let i=0;i<22;i++){
          const c=Math.floor((i*37+t*8)%cols),r=(i*7)%rows,p=points[r][c];
          const pulse=(Math.sin(t*3+i)*.5+.5);
          ctx.beginPath();ctx.arc(p.x,p.y,1.2+pulse*2.0,0,Math.PI*2);
          ctx.fillStyle=i%4===0?'rgba(111,255,231,.95)':'rgba(91,224,255,.9)';
          ctx.shadowBlur=12;ctx.shadowColor='#36dfff';ctx.fill();ctx.shadowBlur=0;
        }
        // Floating horizon arcs
        ctx.beginPath();ctx.ellipse(w*.5,h*.26,w*.31,12,0,Math.PI,Math.PI*2);
        ctx.strokeStyle='rgba(65,217,255,.18)';ctx.lineWidth=1;ctx.stroke();
        raf=requestAnimationFrame(draw);
      }
      resize();window.addEventListener('resize',resize);draw();
      window.addEventListener('pagehide',()=>cancelAnimationFrame(raf),{once:true});
    })();
    </script>
    """.replace("HEIGHT", str(int(height)))
    components.html(html, height=height, scrolling=False)

# ---------------- AUTHENTICATION ----------------

def authentication_screen():
    st.markdown("<div style='height:3vh'></div>", unsafe_allow_html=True)
    left, center, right = st.columns([1.05, 1.35, 1.05], gap="large")
    with left:
        st.markdown('<div class="nx-panel">', unsafe_allow_html=True)
        st.markdown('<div class="nx-kicker">SECURITY INTELLIGENCE</div><h2 class="nx-glow">NEXUS</h2>', unsafe_allow_html=True)
        st.write("A unified access-control and security monitoring environment.")
        st.markdown("---")
        st.markdown("**01 / Identity verification**")
        st.caption("Secure account authentication")
        st.markdown("**02 / Session awareness**")
        st.caption("Monitor active NEXUS sessions")
        st.markdown("**03 / Threat correlation**")
        st.caption("Turn security events into readable incidents")
        st.markdown("</div>", unsafe_allow_html=True)
    with center:
        st.markdown('<div style="text-align:center"><div class="nx-kicker">WELCOME TO THE NETWORK</div>'
                    '<div class="nx-title nx-glow">NEXUS</div><div class="nx-sub">SMART USER ACCESS CONTROL & CYBER THREAT DETECTION</div></div>',
                    unsafe_allow_html=True)
        animated_globe(210)
        mode = st.radio("ACCESS PORTAL", ["Login", "Create Account"], horizontal=True)
        if mode == "Login":
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("SECURE LOGIN", use_container_width=True)
            if submitted:
                auth = AuthenticationService()
                try:
                    result = auth.login(username, password, source_ip=get_client_ip(), device_info=get_client_info())
                except Exception as error:
                    st.error(str(error))
                    result = {"success": False}
                finally:
                    auth.close()
                if result.get("success"):
                    st.session_state["nexus_token"] = result["token"]
                    st.success("Login successful.")
                    st.rerun()
                else:
                    st.error(result.get("message", "Login failed."))
        else:
            with st.form("register_form"):
                new_username = st.text_input("Choose username")
                email = st.text_input("Email (optional)")
                new_password = st.text_input("Create password", type="password")
                confirm = st.text_input("Confirm password", type="password")
                submitted = st.form_submit_button("CREATE ACCOUNT", use_container_width=True)
            if submitted:
                if new_password != confirm:
                    st.error("Passwords do not match.")
                else:
                    auth = AuthenticationService()
                    try:
                        auth.register_user(new_username, email, new_password)
                        st.success("Account created. You can now log in.")
                    except Exception as error:
                        st.error(str(error))
                    finally:
                        auth.close()
        st.caption("NEXUS educational security prototype • Use only accounts you are authorized to manage.")
    with right:
        st.markdown('<div class="nx-panel"><div class="nx-kicker">SYSTEM STATUS</div>', unsafe_allow_html=True)
        st.markdown('<h3 class="nx-glow">● ONLINE</h3>', unsafe_allow_html=True)
        st.caption("Authentication gateway")
        st.markdown("---")
        st.caption("Protected workspace")
        st.caption("Role-based access")
        st.caption("Security event logging")
        st.markdown("</div>", unsafe_allow_html=True)


# ---------------- USER PORTAL ----------------

def user_portal(user):
    section_title("USER PORTAL", "YOUR ACCOUNT  /  ACCESS STATUS  /  SECURITY ACTIVITY")
    st.markdown(f'<div class="nx-panel"><div class="nx-kicker">AUTHENTICATED USER</div><h2>Welcome, {user["username"]}</h2>'
                '<span class="nx-pill">ACCOUNT SESSION ACTIVE</span></div>', unsafe_allow_html=True)
    a, b = st.columns(2)
    a.metric("ACCOUNT ROLE", user["role"].upper())
    b.metric("ACCESS STATUS", "ACTIVE")
    st.markdown("### Your Recent Activity")
    own_events = [e for e in get_events() if e.get("username", "").lower() == user["username"].lower()]
    if own_events:
        st.dataframe(pd.DataFrame(own_events), use_container_width=True, hide_index=True)
    else:
        st.info("No activity recorded yet.")
    st.markdown("### Account Security")
    st.info("Your NEXUS login sessions and security events are recorded by the monitoring system.")


# ---------------- ADMIN COMMAND CENTER ----------------

def admin_overview():
    section_title("COMMAND CENTER", "SECURITY OPERATIONS  /  ADMINISTRATOR OVERVIEW")
    users, events, alerts, sessions = get_users(), get_events(), get_alerts(), get_sessions()
    failed = sum(1 for e in events if e.get("event_type") == "LOGIN" and e.get("status") == "FAILED")
    blocked = sum(1 for u in users if u.get("status") != "active")
    open_alerts = sum(1 for a in alerts if a.get("status") == "open")
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("REGISTERED USERS",len(users)); c2.metric("ACTIVE SESSIONS",len(sessions))
    c3.metric("FAILED LOGINS",failed); c4.metric("BLOCKED / LOCKED",blocked); c5.metric("OPEN ALERTS",open_alerts)
    animated_globe(300)
    st.markdown("### Security Event Activity")
    if events:
        df=pd.DataFrame(events)
        if {"event_type","status"}.issubset(df.columns):
            counts=df.groupby(["event_type","status"]).size().reset_index(name="count")
            fig=px.bar(counts,x="event_type",y="count",color="status",barmode="group",
                       template="plotly_dark",title="Recorded Security Events",
                       color_discrete_sequence=["#39d9ff","#527fff","#ffb45b"])
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
                              font_color="#dcecff",legend_title_text="")
            st.plotly_chart(fig,use_container_width=True)
        st.markdown("### Latest Security Events")
        st.dataframe(pd.DataFrame(events[:10]),use_container_width=True,hide_index=True)
    else:
        st.info("Waiting for security events.")
    if st.button("REFRESH OVERVIEW"):
        st.rerun()


# ---------------- LIVE MONITOR ----------------

def live_monitor():
    section_title("LIVE LOGIN MONITOR", "AUTOMATIC REFRESH  /  AUTHENTICATION ACTIVITY")
    @st.fragment(run_every="5s")
    def monitor_panel():
        events,sessions=get_events(),get_sessions()
        c1,c2,c3=st.columns(3)
        c1.metric("ACTIVE SESSIONS",len(sessions))
        c2.metric("SUCCESSFUL LOGINS",sum(1 for e in events if e.get("event_type")=="LOGIN" and e.get("status")=="SUCCESS"))
        c3.metric("FAILED LOGINS",sum(1 for e in events if e.get("event_type")=="LOGIN" and e.get("status")=="FAILED"))
        st.markdown("### Current Active Sessions")
        if sessions: st.dataframe(pd.DataFrame(sessions),use_container_width=True,hide_index=True)
        else: st.info("No active sessions.")
        st.markdown("### Latest Login Events")
        login_events=[e for e in events if e.get("event_type")=="LOGIN"]
        if login_events: st.dataframe(pd.DataFrame(login_events[:30]),use_container_width=True,hide_index=True)
        else: st.info("No login events yet.")
        st.caption("Refreshes every 5 seconds. Monitoring is limited to NEXUS accounts and sessions.")
    monitor_panel()


# ---------------- USER MANAGEMENT ----------------

def user_management(current_user):
    section_title("USER MANAGEMENT", "REGISTERED ACCOUNTS  /  ACCESS CONTROL")
    users=get_users()
    if users: st.dataframe(pd.DataFrame(users),use_container_width=True,hide_index=True)
    st.markdown("### Manage User Account")
    selectable=[u["username"] for u in users if u.get("role")=="user"]
    if not selectable:
        st.info("No normal user accounts available."); return
    target=st.selectbox("Select account",selectable)
    action=st.selectbox("Choose action",["Block account","Unblock account","Lock account"])
    if st.button("APPLY ACCOUNT ACTION"):
        db=get_db()
        try:
            target_user=db.get_user(target)
            if not target_user or target_user["role"]!="user":
                st.error("This account cannot be managed here."); return
            new_status={"Block account":"blocked","Lock account":"locked","Unblock account":"active"}[action]
            db.update_user_status(target,new_status)
            if new_status!="active": db.revoke_user_sessions(target_user["id"])
            db.add_audit_log(current_user["username"],action.upper().replace(" ","_"),target,
                             f"Account status changed to {new_status}.")
            st.success(f"{target} is now {new_status}.")
        finally: db.close()
        st.rerun()


# ---------------- THREAT DETECTION ----------------

def threat_center():
    section_title("THREAT DETECTION", "RULE-BASED AUTHENTICATION MONITORING")
    events,alerts=get_events(),get_alerts()
    st.markdown('<div class="nx-panel"><div class="nx-kicker">ACTIVE DETECTION RULES</div>'
                '<p>Repeated failed logins</p><p>Blocked or locked account login attempts</p>'
                '<p>Authentication denied events</p><p>Security alerts created by the login system</p></div>',
                unsafe_allow_html=True)
    st.markdown("### Detected Alerts")
    if alerts:
        st.dataframe(pd.DataFrame(alerts),use_container_width=True,hide_index=True)
        st.markdown("### Update Alert Status")
        selected=st.selectbox("Select alert ID",[a["id"] for a in alerts])
        status=st.selectbox("New status",["open","investigating","resolved"])
        if st.button("UPDATE ALERT"):
            db=get_db()
            try: db.update_alert_status(selected,status)
            finally: db.close()
            st.success("Alert updated."); st.rerun()
    else: st.info("No alerts detected yet.")
    st.caption("This prototype uses predefined rules, not machine learning.")


# ---------------- INCIDENT CENTER ----------------

def incident_center():
    section_title("INCIDENT CENTER", "CORRELATED EVENTS  /  RULE-BASED INCIDENT GROUPING")
    events=get_events()
    incidents=IncidentCorrelator().correlate_events(events)
    high=sum(1 for x in incidents if x["severity"]=="HIGH")
    medium=sum(1 for x in incidents if x["severity"]=="MEDIUM")
    low=sum(1 for x in incidents if x["severity"]=="LOW")
    a,b,c,d=st.columns(4)
    a.metric("TOTAL INCIDENTS",len(incidents)); b.metric("HIGH",high); c.metric("MEDIUM",medium); d.metric("LOW",low)
    st.markdown("### Correlation Logic")
    st.caption("Events are grouped by username and source IP. The rules identify repeated failed logins, suspicious network events and denied access. Incidents are derived from the latest stored events and are not separately persisted.")
    if incidents:
        frame=pd.DataFrame(incidents)
        st.dataframe(frame,use_container_width=True,hide_index=True)
        st.download_button("EXPORT INCIDENTS CSV",frame.to_csv(index=False).encode("utf-8"),
                           file_name="nexus_incidents.csv",mime="text/csv")
        fig=px.pie(frame,names="severity",title="Incident Severity Distribution",hole=.58,
                   color="severity",color_discrete_map={"HIGH":"#ff5577","MEDIUM":"#ffbd59","LOW":"#39d9ff"})
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",font_color="#dcecff")
        st.plotly_chart(fig,use_container_width=True)
    else:
        st.info("No correlated incidents found yet. Generate test events using your own NEXUS test accounts.")


# ---------------- BLOCKED ACCOUNTS ----------------

def blocked_accounts():
    section_title("BLOCKED ACCOUNTS","CURRENT ACCOUNT RESTRICTIONS")
    blocked=[u for u in get_users() if u.get("status")!="active"]
    if blocked: st.dataframe(pd.DataFrame(blocked),use_container_width=True,hide_index=True)
    else: st.success("No blocked or locked accounts.")


# ---------------- ACTIVE SESSIONS ----------------

def active_sessions():
    section_title("ACTIVE SESSIONS","CURRENT AUTHENTICATED USER SESSIONS")
    sessions=get_sessions()
    if sessions:
        st.dataframe(pd.DataFrame(sessions),use_container_width=True,hide_index=True)
        selected=st.selectbox("Select session to revoke",[s["id"] for s in sessions])
        if st.button("REVOKE SELECTED SESSION"):
            db=get_db()
            try: db.revoke_session(selected)
            finally: db.close()
            st.success("Session revoked."); st.rerun()
    else: st.info("No active sessions.")


# ---------------- AUDIT LOGS ----------------

def audit_logs():
    section_title("SECURITY AUDIT LOGS","ADMIN ACTIONS  /  ACCOUNT ACTIVITY")
    logs=get_audit()
    if logs: st.dataframe(pd.DataFrame(logs),use_container_width=True,hide_index=True)
    else: st.info("No audit records available.")


# ---------------- DSA LAB ----------------

def dsa_lab():
    section_title("DSA LABORATORY","DATA STRUCTURES  /  FIVE SORTING ALGORITHMS")
    tab1,tab2,tab3=st.tabs(["Data Structures","Sorting Algorithms","Performance"])
    with tab1:
        st.markdown("### Queue — FIFO")
        queue=Queue()
        for value in ["LOGIN","FAILED","ALERT"]: queue.enqueue(value)
        st.write("Queue contents:",queue.items); st.write("Dequeue:",queue.dequeue()); st.write("Remaining:",queue.items)
        st.divider(); st.markdown("### Stack — LIFO")
        stack=Stack()
        for value in ["LOGIN","VERIFY","LOGOUT"]: stack.push(value)
        st.write("Stack contents:",stack.items); st.write("Pop:",stack.pop()); st.write("Remaining:",stack.items)
        st.divider(); st.markdown("### Singly Linked List")
        singly=SinglyLinkedList()
        for value in ["Event 1","Event 2","Event 3"]: singly.insert(value)
        st.write(singly.display())
        st.divider(); st.markdown("### Doubly Linked List")
        doubly=DoublyLinkedList()
        for value in ["Low","Medium","High"]: doubly.insert(value)
        st.write("Forward:",doubly.display_forward()); st.write("Backward:",doubly.display_backward())
    with tab2:
        sample=[
            {"severity":"LOW","incident":"Access denied"},
            {"severity":"HIGH","incident":"Repeated login failures"},
            {"severity":"MEDIUM","incident":"Suspicious event"},
            {"severity":"HIGH","incident":"Account lockout"},
            {"severity":"LOW","incident":"Unknown page access"}
        ]
        methods={"Bubble Sort":SortingAlgorithms.bubble_sort,"Insertion Sort":SortingAlgorithms.insertion_sort,
                 "Merge Sort":SortingAlgorithms.merge_sort,"Shell Sort":SortingAlgorithms.shell_sort,
                 "Heap Sort":SortingAlgorithms.heap_sort}
        selected=st.selectbox("Choose sorting algorithm",list(methods.keys()))
        if st.button("RUN SORTING ALGORITHM"):
            result=methods[selected](sample)
            st.dataframe(pd.DataFrame(result),use_container_width=True,hide_index=True)
    with tab3:
        st.markdown("### Sorting Performance Test")
        st.code("python test_sorting_performance.py",language="powershell")
        st.info("Execution times depend on your computer and input size.")


# ---------------- MAIN ROUTER ----------------

st.sidebar.markdown(
    '<div style="padding:5px 0 16px"><div style="font-size:28px;font-weight:900;letter-spacing:3px;color:#54dcff;text-shadow:0 0 18px rgba(56,217,255,.35)">NEXUS</div>'
    '<div style="font-size:9px;letter-spacing:2px;color:#7898bd;font-weight:800">SECURITY OPERATIONS</div></div>',
    unsafe_allow_html=True
)

current_user=load_current_user()
if not current_user:
    st.session_state.pop("nexus_token",None)
    st.session_state.pop("nexus_user",None)
    authentication_screen()
else:
    st.session_state["nexus_user"]=current_user
    st.sidebar.markdown("---")
    st.sidebar.caption("SIGNED IN AS")
    st.sidebar.markdown(f"**{current_user['username']}**")
    st.sidebar.caption(current_user["role"].upper())
    if current_user["role"]=="admin":
        pages=["Command Center","Live Login Monitor","User Management","Threat Detection",
               "Incident Center","Blocked Accounts","Active Sessions","Security Audit Logs","DSA Laboratory"]
    else:
        pages=["My Account"]
    page=st.sidebar.radio("NAVIGATION",pages)
    st.sidebar.markdown("---")
    st.sidebar.caption("NEXUS • ACCESS CONTROL SYSTEM")
    if st.sidebar.button("LOG OUT",use_container_width=True):
        logout()
    if page=="Command Center": admin_overview()
    elif page=="Live Login Monitor": live_monitor()
    elif page=="User Management": user_management(current_user)
    elif page=="Threat Detection": threat_center()
    elif page=="Incident Center": incident_center()
    elif page=="Blocked Accounts": blocked_accounts()
    elif page=="Active Sessions": active_sessions()
    elif page=="Security Audit Logs": audit_logs()
    elif page=="DSA Laboratory": dsa_lab()
    elif page=="My Account": user_portal(current_user)
