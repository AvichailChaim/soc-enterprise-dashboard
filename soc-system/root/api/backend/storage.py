import sqlite3
import json
import os

# הגדרת נתיב אבסולוטי יציב
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "siem.db")

def init():
    os.makedirs(BASE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # טבלת לוגים
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            source TEXT,
            ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # טבלת התראות
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            severity TEXT,
            score INTEGER,
            description TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(log_id) REFERENCES logs(id)
        )
    """)
    conn.commit()
    conn.close()

# הרצת ה-init בבטחה
try:
    init()
except Exception as e:
    print(f"[-] Database initialization failed: {e}")

# --- הפונקציות ש-main.py מחפש וכרגע חסרות לו ---

def save_event(event):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO logs (username, action, source, ip)
        VALUES (?, ?, ?, ?)
    """, (event["user"], event["action"], event["source"], event["ip"]))
    last_id = c.lastrowid
    conn.commit()
    conn.close()
    return last_id

def save_alert(log_id, alert_details):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts (log_id, severity, score, description)
        VALUES (?, ?, ?, ?)
    """, (log_id, alert_details["severity"], alert_details["score"], alert_details["description"]))
    conn.commit()
    conn.close()

def get_events():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT a.id, a.severity, a.score, a.description, a.timestamp, l.username, l.source, l.ip 
        FROM alerts a 
        JOIN logs l ON a.log_id = l.id 
        ORDER BY a.id DESC LIMIT 50
    """)
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows