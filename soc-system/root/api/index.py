import os
from typing import Optional

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# מוגדר ב-Vercel Environment Variables. אם לא מוגדר - האימות מדולג (מצב פיתוח בלבד).
AGENT_TOKEN = os.environ.get("AGENT_TOKEN")


def get_db_connection():
    # ה-DATABASE_URL מוגדר ב-Vercel -> Settings -> Environment Variables
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    return conn


def ensure_schema():
    """יוצר/משדרג את הסכימה בצורה אידמפוטנטית - בטוח להריץ בכל cold start."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY,
            user_name TEXT,
            action TEXT,
            source TEXT,
            ip TEXT
        )
        """
    )
    for col, definition in [
        ("ts", "TIMESTAMPTZ DEFAULT now()"),
        ("host", "TEXT"),
        ("severity", "TEXT"),
        ("score", "INTEGER"),
        ("description", "TEXT"),
    ]:
        cur.execute(f"ALTER TABLE events ADD COLUMN IF NOT EXISTS {col} {definition}")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            event_id INTEGER REFERENCES events(id),
            severity TEXT,
            score INTEGER,
            description TEXT,
            mitre TEXT,
            ts TIMESTAMPTZ DEFAULT now()
        )
        """
    )
    conn.commit()
    cur.close()
    conn.close()


try:
    ensure_schema()
except Exception as _e:
    print(f"[-] schema init failed: {_e}")


class Event(BaseModel):
    user: str
    action: str
    source: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None


# מיפוי אירוע -> טכניקת MITRE ATT&CK משוערת, לצורך תצוגה בממשק
MITRE_MAP = {
    "login_failed": "T1110 Brute Force",
    "login_success": "T1078 Valid Accounts",
    "user_created": "T1136 Create Account",
    "audit_log_cleared": "T1070.001 Clear Windows Event Logs",
    "file_permission_denied": "T1005 Data from Local System",
    "network_file_access_failed": "T1021 Remote Services",
    "account_locked_out": "T1110 Brute Force",
    "explicit_credential_logon": "T1550 Use Alternate Authentication Material",
    "privileged_logon": "T1078.003 Valid Accounts: Local Accounts",
    "new_service_installed": "T1543.003 Windows Service",
    "process_created": "T1059 Command and Scripting Interpreter",
}

# ניקוד בסיסי לכל סוג אירוע (score, description)
BASE_SCORES = {
    "file_permission_denied": (55, "Unauthorized local file access attempt blocked (Access Denied)."),
    "network_file_access_failed": (65, "Unauthorized network/file share access attempt with bad credentials."),
    "login_failed": (40, "Failed local login attempt."),
    "user_created": (60, "New local user account was created."),
    "audit_log_cleared": (95, "CRITICAL: Windows Security log was cleared!"),
    "account_locked_out": (70, "Account locked out after repeated failed logins (brute-force indicator)."),
    "explicit_credential_logon": (50, "Explicit credential logon detected (possible lateral movement / pass-the-hash)."),
    "privileged_logon": (35, "Privileged (admin-level) logon detected."),
    "new_service_installed": (75, "New Windows service installed (possible persistence mechanism)."),
    "process_created": (20, "New process created."),
}


def analyze_event(e, cur):
    """מנוע ניקוד + קורלציה בסיסית (brute force) - רץ בכל אירוע נכנס."""
    score = 0
    parts = []

    if e["action"] in BASE_SCORES:
        s, desc = BASE_SCORES[e["action"]]
        score += s
        parts.append(desc)

    user_lower = (e["user"] or "").lower()
    if "admin" in user_lower or "administrator" in user_lower:
        score += 20
        parts.append("Target user has administrative keywords.")

    # קורלציה: כמה כשלונות התחברות מאותו משתמש/IP ב-5 הדקות האחרונות
    if e["action"] in ("login_failed", "account_locked_out"):
        cur.execute(
            """
            SELECT count(*) FROM events
            WHERE action IN ('login_failed', 'account_locked_out')
              AND (user_name = %s OR ip = %s)
              AND ts > now() - interval '5 minutes'
            """,
            (e["user"], e.get("ip")),
        )
        recent_fails = cur.fetchone()[0]
        if recent_fails >= 5:
            score += 40
            parts.append(f"Brute-force pattern detected: {recent_fails} failed logins in last 5 minutes.")

    description = " | ".join(parts) if parts else "Normal system activity."
    mitre = MITRE_MAP.get(e["action"], "")

    if score >= 70:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    elif score > 0:
        severity = "Low"
    else:
        severity = None

    return {"severity": severity, "score": score, "description": description, "mitre": mitre}


def check_auth(x_agent_token: Optional[str]):
    if AGENT_TOKEN and x_agent_token != AGENT_TOKEN:
        raise HTTPException(status_code=401, detail="invalid or missing agent token")


@app.post("/api/event")
def create_event(e: Event, x_agent_token: Optional[str] = Header(default=None)):
    check_auth(x_agent_token)
    host = e.host or e.source
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        result = analyze_event({"user": e.user, "action": e.action, "ip": e.ip}, cur)
        cur.execute(
            """
            INSERT INTO events (user_name, action, source, host, ip, severity, score, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """,
            (e.user, e.action, e.source, host, e.ip, result["severity"], result["score"], result["description"]),
        )
        event_id = cur.fetchone()[0]
        if result["severity"]:
            cur.execute(
                """
                INSERT INTO alerts (event_id, severity, score, description, mitre)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (event_id, result["severity"], result["score"], result["description"], result["mitre"]),
            )
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok", "event_id": event_id, **result}
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@app.get("/api/events")
def get_events(limit: int = 200):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, ts as timestamp, user_name as user, action,
               COALESCE(host, source) as host, ip as source_ip,
               severity, score, description
        FROM events ORDER BY id DESC LIMIT %s
        """,
        (limit,),
    )
    rows = cur.fetchall()
    for r in rows:
        r["mitre"] = MITRE_MAP.get(r["action"], "")
    cur.close()
    conn.close()
    return rows


@app.get("/api/alerts")
def get_alerts(limit: int = 100):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT a.id, a.severity, a.score, a.description, a.mitre, a.ts as timestamp,
               e.id as event_id, e.user_name as user, e.action,
               COALESCE(e.host, e.source) as host, e.ip as source_ip
        FROM alerts a JOIN events e ON a.event_id = e.id
        ORDER BY a.id DESC LIMIT %s
        """,
        (limit,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


@app.get("/api/stats")
def get_stats():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT count(*) FROM events")
    total_events = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM alerts WHERE severity = 'High'")
    critical_alerts = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM alerts WHERE severity = 'Medium'")
    medium_alerts = cur.fetchone()[0]
    cur.execute("SELECT count(DISTINCT ip) FROM events WHERE ip IS NOT NULL")
    unique_ips = cur.fetchone()[0]

    cur.execute(
        """
        SELECT ip, count(*) c FROM events
        WHERE ip IS NOT NULL GROUP BY ip ORDER BY c DESC LIMIT 5
        """
    )
    top_ips = [{"ip": row[0], "c": row[1]} for row in cur.fetchall()]

    cur.execute(
        """
        SELECT user_name, count(*) c FROM events
        WHERE user_name IS NOT NULL GROUP BY user_name ORDER BY c DESC LIMIT 5
        """
    )
    top_users = [{"user_name": row[0], "c": row[1]} for row in cur.fetchall()]

    # נתונים לגרף הראשי + heatmap - 24 שעות אחרונות, 6 חלונות של 4 שעות
    cur.execute(
        """
        SELECT action, severity, extract(hour from ts)::int as hr
        FROM events WHERE ts > now() - interval '24 hours'
        """
    )
    recent = cur.fetchall()
    cur.close()
    conn.close()

    buckets = [0, 4, 8, 12, 16, 20]

    def bucket_index(hr):
        for i in range(len(buckets) - 1, -1, -1):
            if hr >= buckets[i]:
                return i
        return 0

    logs_series = [0] * 6
    alerts_series = [0] * 6
    anomalies_series = [0] * 6

    categories = {
        "Auth": {"login_failed", "login_success", "account_locked_out", "explicit_credential_logon", "privileged_logon"},
        "Endpoint": {"file_permission_denied", "process_created"},
        "Network": {"network_file_access_failed"},
        "Privilege": {"user_created", "privileged_logon"},
        "Malware": {"audit_log_cleared", "new_service_installed"},
    }
    heat = {cat: [0] * 6 for cat in categories}

    for row in recent:
        action, severity, hr = row
        bi = bucket_index(hr or 0)
        logs_series[bi] += 1
        if severity:
            alerts_series[bi] += 1
        if severity == "High":
            anomalies_series[bi] += 1
        for cat, actions in categories.items():
            if action in actions:
                heat[cat][bi] += 1

    return {
        "total_events": total_events,
        "critical_alerts": critical_alerts,
        "medium_alerts": medium_alerts,
        "unique_ips": unique_ips,
        "top_ips": top_ips,
        "top_users": top_users,
        "chart": {
            "labels": ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
            "logs": logs_series,
            "alerts": alerts_series,
            "anomalies": anomalies_series,
        },
        "heatmap": [{"label": cat, "values": vals} for cat, vals in heat.items()],
    }


@app.get("/api/investigate/{event_id}")
def investigate(event_id: int):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, ts as timestamp, user_name as user, action,
               COALESCE(host, source) as host, ip as source_ip, severity, score, description
        FROM events WHERE id = %s
        """,
        (event_id,),
    )
    event = cur.fetchone()
    if not event:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="event not found")
    event["mitre"] = MITRE_MAP.get(event["action"], "")

    cur.execute(
        """
        SELECT id, ts as timestamp, user_name as user, action,
               COALESCE(host, source) as host, ip as source_ip, severity, score, description
        FROM events
        WHERE id != %s AND (user_name = %s OR ip = %s OR COALESCE(host, source) = %s)
          AND ts BETWEEN %s - interval '30 minutes' AND %s + interval '30 minutes'
        ORDER BY ts DESC LIMIT 50
        """,
        (event_id, event["user"], event["source_ip"], event["host"], event["timestamp"], event["timestamp"]),
    )
    related = cur.fetchall()
    for r in related:
        r["mitre"] = MITRE_MAP.get(r["action"], "")
    cur.close()
    conn.close()
    return {"event": event, "related": related}


@app.get("/api/agent-update")
def agent_update():
    """endpoint שממנו ה-agent המותקן על תחנות הקצה מושך גרסה מעודכנת של עצמו."""
    path = os.path.join(os.path.dirname(__file__), "agent", "send.ps1")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return PlainTextResponse(f.read())
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
