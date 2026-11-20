import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = BASE_DIR / "database" / "cyber_threats.db"

class DatabaseManager:
    def __init__(self, db_path=None):
        path = Path(db_path) if db_path else DEFAULT_DB
        if not path.is_absolute(): path = BASE_DIR / path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.create_tables()

    def create_tables(self):
        self.connection.executescript("""
        CREATE TABLE IF NOT EXISTS security_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT,username TEXT,source_ip TEXT,event_type TEXT,status TEXT);
        CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT,source_ip TEXT,incident_type TEXT,severity TEXT,related_events INTEGER);
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE COLLATE NOCASE NOT NULL,email TEXT DEFAULT '',password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',status TEXT NOT NULL DEFAULT 'active',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,token_hash TEXT UNIQUE NOT NULL,source_ip TEXT,device_info TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,revoked INTEGER NOT NULL DEFAULT 0,FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,username TEXT,source_ip TEXT,event_type TEXT,status TEXT,details TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,username TEXT,source_ip TEXT,threat TEXT,severity TEXT,details TEXT,status TEXT DEFAULT 'open');
        CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,actor TEXT,action TEXT,target TEXT,details TEXT);
        """)
        self.connection.commit()

    def _rows(self, sql, params=()): return [dict(r) for r in self.connection.execute(sql, params).fetchall()]
    def save_logs(self, events):
        self.connection.executemany("INSERT INTO security_logs(timestamp,username,source_ip,event_type,status) VALUES(?,?,?,?,?)",[(str(e.get('timestamp','')),e.get('username',''),e.get('source_ip',''),e.get('event_type',''),e.get('status','')) for e in events]); self.connection.commit()
    def save_incidents(self, incidents):
        self.connection.executemany("INSERT INTO incidents(username,source_ip,incident_type,severity,related_events) VALUES(?,?,?,?,?)",[(i.get('username',''),i.get('source_ip',''),i.get('incident_type',''),i.get('severity',''),i.get('related_events',0)) for i in incidents]); self.connection.commit()
    def get_logs(self): return self._rows('SELECT * FROM security_logs ORDER BY id DESC')
    def get_incidents(self): return self._rows('SELECT * FROM incidents ORDER BY id DESC')
    def create_user(self, username, email, password_hash, role='user'):
        cur=self.connection.execute('INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)',(username.strip(),email or '',password_hash,role)); self.connection.commit(); return cur.lastrowid
    def get_user(self, username):
        rows=self._rows('SELECT * FROM users WHERE username=? COLLATE NOCASE',(username,)); return rows[0] if rows else None
    def get_session_user(self, token_hash):
        rows=self._rows('SELECT u.id,u.username,u.email,u.role,u.status FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked=0',(token_hash,)); return rows[0] if rows else None
    def add_session(self, user_id, token_hash, source_ip, device_info):
        self.connection.execute('INSERT INTO sessions(user_id,token_hash,source_ip,device_info) VALUES(?,?,?,?)',(user_id,token_hash,source_ip,device_info)); self.connection.commit()
    def revoke_token(self, token_hash): self.connection.execute('UPDATE sessions SET revoked=1 WHERE token_hash=?',(token_hash,)); self.connection.commit()
    def revoke_user_sessions(self, user_id): self.connection.execute('UPDATE sessions SET revoked=1 WHERE user_id=?',(user_id,)); self.connection.commit()
    def get_all_users(self): return self._rows('SELECT id,username,email,role,status,created_at FROM users ORDER BY id DESC')
    def update_user_status(self, username, status): self.connection.execute('UPDATE users SET status=? WHERE username=? COLLATE NOCASE',(status,username)); self.connection.commit()
    def get_active_sessions(self): return self._rows("SELECT s.id,u.username,u.role,s.source_ip,s.device_info,s.created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.revoked=0 AND u.status='active' ORDER BY s.id DESC")
    def add_security_event(self, username, source_ip, event_type, status, details=''):
        self.connection.execute('INSERT INTO security_events(username,source_ip,event_type,status,details) VALUES(?,?,?,?,?)',(username,source_ip,event_type,status,details)); self.connection.commit()
        if event_type=='LOGIN' and status=='FAILED':
            n=self.connection.execute("SELECT COUNT(*) FROM security_events WHERE username=? AND event_type='LOGIN' AND status='FAILED' AND timestamp>=datetime('now','-15 minutes')",(username,)).fetchone()[0]
            if n==3: self.connection.execute("INSERT INTO alerts(username,source_ip,threat,severity,details) VALUES(?,?,?,?,?)",(username,source_ip,'Repeated Failed Login Attempts','HIGH',f'{n} failed attempts in 15 minutes')); self.connection.commit()
    def get_security_events(self, limit=500): return self._rows('SELECT * FROM security_events ORDER BY id DESC LIMIT ?',(int(limit),))
    def get_alerts(self, limit=500): return self._rows('SELECT * FROM alerts ORDER BY id DESC LIMIT ?',(int(limit),))
    def update_alert_status(self, alert_id, status): self.connection.execute('UPDATE alerts SET status=? WHERE id=?',(status,alert_id)); self.connection.commit()
    def add_audit_log(self, actor, action, target, details): self.connection.execute('INSERT INTO audit_logs(actor,action,target,details) VALUES(?,?,?,?)',(actor,action,target,details)); self.connection.commit()
    def get_audit_logs(self, limit=500): return self._rows('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?',(int(limit),))
    def close(self): self.connection.close()
