import os
import secrets
import hmac
import smtplib
from email.mime.text import MIMEText
from typing import Optional

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
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

# פרטי ההתחברות לדשבורד עצמו (מנהל המערכת מגדיר אותם מראש ב-Vercel Environment Variables).
# אם לא מוגדרים בכלל - הדשבורד יישאר פתוח בלי התחברות (מצב פיתוח בלבד, לא מומלץ בייצור).
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
SESSION_HOURS = 24

# התראות מייל ל-Critical/High (Gmail SMTP + App Password). אם לא מוגדרים - שליחת המייל
# מדולגת בשקט (לא שובר קליטת אירועים אם המנהל עדיין לא הגדיר את זה).
SMTP_USER = os.environ.get("SMTP_USER")            # כתובת ה-Gmail השולחת
SMTP_APP_PASSWORD = os.environ.get("SMTP_APP_PASSWORD")   # App Password (לא הסיסמה הרגילה)
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO", SMTP_USER)   # נמען ההתראות (ברירת מחדל: אותה כתובת)


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
        ("lan_ip", "TEXT"),
        ("wan_ip", "TEXT"),
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
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT,
            created_at TIMESTAMPTZ DEFAULT now(),
            expires_at TIMESTAMPTZ
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS commands (
            id SERIAL PRIMARY KEY,
            host TEXT,
            command TEXT,
            password TEXT,
            maintenance_minutes INTEGER,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT now(),
            delivered_at TIMESTAMPTZ
        )
        """
    )
    conn.commit()
    cur.close()
    conn.close()


def cleanup_legacy_hosts():
    """סוכנים ישנים (לפני התיקון) שלחו host שמכיל את סוג האירוע (למשל "MOSHEBI-WIN10 (Event ID 4624)")
    במקום שם מחשב נקי - מה שגרם לאותו מחשב להופיע בכמה שורות שונות בעמוד Computers, ולפקודות מרחוק
    (Stop/Start/Uninstall) שלא מגיעות ליעד הנכון כי ה-Watchdog מחפש לפי שם המחשב הנקי. מנקים את זה
    אחת ולתמיד (אידמפוטנטי - בטוח להריץ בכל cold start, אין השפעה אחרי שהניקוי כבר בוצע)."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(r"UPDATE events SET host = regexp_replace(host, '\s*\(Event ID \d+\)\s*$', '') WHERE host ~ '\(Event ID \d+\)\s*$'")
    conn.commit()
    cur.close()
    conn.close()


try:
    ensure_schema()
    cleanup_legacy_hosts()
except Exception as _e:
    print(f"[-] schema init failed: {_e}")


class Event(BaseModel):
    user: str
    action: str
    source: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    lan_ip: Optional[str] = None
    reason: Optional[str] = None


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
    "malware_detected": "T1486 Data Encrypted for Impact (Ransomware) / Malware",
    "malware_blocked": "T1486 Data Encrypted for Impact (Ransomware) / Malware",
    "defender_protection_disabled": "T1562.001 Disable or Modify Tools",
    "agent_tamper_detected": "T1489 Service Stop / Tamper Attempt",
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
    "malware_detected": (90, "Malware/ransomware-family threat detected by Windows Defender."),
    "malware_blocked": (60, "Windows Defender detected and took action against a threat."),
    "defender_protection_disabled": (85, "Real-time protection / antivirus was disabled - possible evasion attempt."),
    "agent_tamper_detected": (95, "CRITICAL: The monitoring agent service was stopped/removed without authorization and was automatically restored by the watchdog."),
}


def analyze_event(e, cur):
    """מנוע ניקוד + קורלציות (brute force, ניסיונות מקבילים, גישה חוזרת שנדחתה) - רץ בכל אירוע נכנס."""
    score = 0
    parts = []

    if e["action"] in BASE_SCORES:
        s, desc = BASE_SCORES[e["action"]]
        score += s
        # אם הסוכן דיווח סיבה מדויקת (למשל "Bad password" מ-Event 4625, או פרטי תהליך/יעד
        # מ-Event 4648) - מציגים אותה במפורש במקום/בנוסף לתיאור הגנרי, כדי שבדשבורד יהיה ברור
        # בדיוק למה קפצה ההתראה, לא רק סוג האירוע הכללי.
        if e.get("reason"):
            if e["action"] in ("login_failed", "account_locked_out", "network_file_access_failed"):
                desc = f"Failed login attempt for user '{e['user']}' - reason: {e['reason']}."
            else:
                desc = e["reason"]
        parts.append(desc)

    user_lower = (e["user"] or "").lower()
    if "admin" in user_lower or "administrator" in user_lower:
        score += 20
        parts.append("Target user has administrative keywords.")

    if e["action"] in ("login_failed", "account_locked_out"):
        # קורלציה 1: יותר מניסיון כושל אחד מאותו משתמש/IP - כל כשלון נוסף מעלה את הניקוד
        cur.execute(
            """
            SELECT count(*) FROM events
            WHERE action IN ('login_failed', 'account_locked_out')
              AND (user_name = %s OR ip = %s)
              AND ts > now() - interval '10 minutes'
            """,
            (e["user"], e.get("ip")),
        )
        recent_fails = cur.fetchone()[0]
        if recent_fails >= 2:
            score += 25
            parts.append(f"Repeated failed login: attempt #{recent_fails + 1} for this user/IP in the last 10 minutes.")
        if recent_fails >= 5:
            score += 40
            parts.append(f"Brute-force pattern detected: {recent_fails} failed logins in last 10 minutes.")

        # קורלציה 2: כמה ניסיונות כושלים (בלי קשר למשתמש/IP) תוך שניות בודדות - סימן לניסיון ממוכן/מקבילי
        cur.execute(
            """
            SELECT count(*) FROM events
            WHERE action IN ('login_failed', 'account_locked_out')
              AND ts > now() - interval '3 seconds'
            """
        )
        concurrent_fails = cur.fetchone()[0]
        if concurrent_fails >= 3:
            score += 50
            parts.append(f"{concurrent_fails} failed login attempts within 3 seconds - possible automated/parallel password attack.")

    if e["action"] in ("file_permission_denied", "network_file_access_failed"):
        # קורלציה 3: כמה ניסיונות גישה/פתיחת קובץ שנדחו מאותו משתמש בזמן קצר - סריקה/ניסיון פריצה, או סימן להתנהגות כופרה
        cur.execute(
            """
            SELECT count(*) FROM events
            WHERE action IN ('file_permission_denied', 'network_file_access_failed')
              AND user_name = %s
              AND ts > now() - interval '2 minutes'
            """,
            (e["user"],),
        )
        recent_denied = cur.fetchone()[0]
        if recent_denied >= 3:
            score += 35
            parts.append(f"{recent_denied} access-denied attempts by this user in last 2 minutes - possible privilege probing or ransomware-style file scanning.")

    description = " | ".join(parts) if parts else "Normal system activity."
    mitre = MITRE_MAP.get(e["action"], "")

    if score >= 90:
        severity = "Critical"
    elif score >= 70:
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


class LoginRequest(BaseModel):
    username: str
    password: str


def check_session(x_session_token: Optional[str]):
    """מגן על נתוני הדשבורד (events/stats/alerts/investigate) - דורש טוקן סשן תקף שהתקבל מ-/api/login.
    אם ADMIN_USERNAME/ADMIN_PASSWORD לא הוגדרו בכלל ב-Vercel, ההתחברות מדולגת (מצב פיתוח בלבד)."""
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        return
    if not x_session_token:
        raise HTTPException(status_code=401, detail="login required")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM sessions WHERE token = %s AND expires_at > now()", (x_session_token,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="session expired or invalid")


@app.post("/api/login")
def login(body: LoginRequest):
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        raise HTTPException(status_code=500, detail="ADMIN_USERNAME/ADMIN_PASSWORD not configured on the server")
    valid = hmac.compare_digest(body.username, ADMIN_USERNAME) and hmac.compare_digest(body.password, ADMIN_PASSWORD)
    if not valid:
        raise HTTPException(status_code=401, detail="invalid username or password")
    token = secrets.token_urlsafe(32)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        f"INSERT INTO sessions (token, username, expires_at) VALUES (%s, %s, now() + interval '{SESSION_HOURS} hours')",
        (token, body.username),
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"token": token}


@app.post("/api/logout")
def logout(x_session_token: Optional[str] = Header(default=None)):
    if x_session_token:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token = %s", (x_session_token,))
        conn.commit()
        cur.close()
        conn.close()
    return {"status": "ok"}


@app.get("/api/agent-token")
def get_agent_token(x_session_token: Optional[str] = Header(default=None)):
    """מאפשר ל-install.ps1 לשלוף את AGENT_TOKEN הנוכחי אוטומטית ע"י התחברות עם משתמש/סיסמה
    של הדשבורד (שהמנהל בוודאות זוכר), במקום להעתיק ידנית ערך סודי שוורסל מסתיר אחרי השמירה."""
    check_session(x_session_token)
    return {"agent_token": AGENT_TOKEN}


def get_wan_ip(request: Request) -> Optional[str]:
    """ה-WAN IP האמיתי נלקח מהבקשה עצמה בצד השרת (לא ממה שהסוכן מדווח על עצמו) -
    כך שאי אפשר לזייף אותו, ותמיד יהיה מדויק בהתאם למי שבאמת שלח את הבקשה ל-Vercel."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def send_alert_email(severity, action, user, host, ip, description, mitre, event_id):
    """שולח מייל התראה על אירוע Critical/High באמצעות Gmail SMTP + App Password.
    רץ כ-BackgroundTask (אחרי שהתגובה ל-agent כבר נשלחה) כדי לא להאט את קליטת האירוע -
    ל-agent יש timeout של 5 שניות על הבקשה, ו-SMTP יכול לפעמים להיות איטי."""
    if not (SMTP_USER and SMTP_APP_PASSWORD and ALERT_EMAIL_TO):
        return
    try:
        subject = f"[SOC {severity}] {action} - {host or 'unknown host'}"
        body = (
            f"Severity: {severity}\n"
            f"Action: {action}\n"
            f"Host: {host}\n"
            f"User: {user}\n"
            f"IP: {ip}\n"
            f"MITRE: {mitre}\n\n"
            f"{description}\n\n"
            f"Event ID: {event_id}\n"
            f"Dashboard: https://soc-enterprise-dashboard-hayanuka.vercel.app"
        )
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL_TO
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
            server.login(SMTP_USER, SMTP_APP_PASSWORD)
            server.sendmail(SMTP_USER, [ALERT_EMAIL_TO], msg.as_string())
    except Exception as ex:
        print(f"[-] alert email failed: {ex}")


@app.post("/api/event")
def create_event(e: Event, request: Request, background_tasks: BackgroundTasks, x_agent_token: Optional[str] = Header(default=None)):
    check_auth(x_agent_token)
    host = e.host or e.source
    wan_ip = get_wan_ip(request)
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        result = analyze_event({"user": e.user, "action": e.action, "ip": e.ip, "reason": e.reason}, cur)
        cur.execute(
            """
            INSERT INTO events (user_name, action, source, host, ip, severity, score, description, lan_ip, wan_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """,
            (e.user, e.action, e.source, host, e.ip, result["severity"], result["score"], result["description"], e.lan_ip, wan_ip),
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
        if result["severity"] in ("Critical", "High"):
            background_tasks.add_task(
                send_alert_email, result["severity"], e.action, e.user, host, e.ip,
                result["description"], result["mitre"], event_id,
            )
        return {"status": "ok", "event_id": event_id, **result}
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@app.get("/api/events")
def get_events(limit: int = 200, x_session_token: Optional[str] = Header(default=None)):
    check_session(x_session_token)
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, ts as timestamp, user_name as user, action,
               COALESCE(host, source) as host, ip as source_ip,
               severity, score, description, lan_ip, wan_ip
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
def get_alerts(limit: int = 100, x_session_token: Optional[str] = Header(default=None)):
    check_session(x_session_token)
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


class HostCommand(BaseModel):
    command: str  # "stop" | "start" | "uninstall"
    password: str
    maintenance_minutes: int = 60


@app.get("/api/hosts")
def get_hosts(x_session_token: Optional[str] = Header(default=None)):
    """רשימת המחשבים שדיווחו אי-פעם, לטובת עמוד ניהול המחשבים בדשבורד."""
    check_session(x_session_token)
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT host,
               max(ts) as last_seen,
               count(*) as event_count,
               count(*) FILTER (WHERE severity IN ('Critical', 'High')) as high_count,
               (array_agg(lan_ip ORDER BY ts DESC))[1] as lan_ip,
               (array_agg(wan_ip ORDER BY ts DESC))[1] as wan_ip
        FROM events
        WHERE host IS NOT NULL
        GROUP BY host
        ORDER BY last_seen DESC
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


@app.post("/api/hosts/{host}/command")
def queue_host_command(host: str, body: HostCommand, x_session_token: Optional[str] = Header(default=None)):
    """מנהל מחובר לדשבורד יכול לתזמן פקודה (עצירה/הפעלה/הסרה) למחשב ספציפי. הפקודה נאספת
    ע"י ה-Watchdog של אותו מחשב (עד 5 דקות), ומבוצעת רק אם הסיסמה תואמת את ה-hash המקומי
    שהוגדר ב-install.ps1 -UninstallPassword על אותו מחשב - כך שגישה לדשבורד לבדה לא מספיקה."""
    check_session(x_session_token)
    if body.command not in ("stop", "start", "uninstall"):
        raise HTTPException(status_code=400, detail="invalid command")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO commands (host, command, password, maintenance_minutes) VALUES (%s, %s, %s, %s)",
        (host, body.command, body.password, body.maintenance_minutes),
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "queued"}


@app.get("/api/agent-command")
def get_agent_command(host: str, response: Response, x_agent_token: Optional[str] = Header(default=None)):
    """נקרא ע"י ה-Watchdog של כל מחשב (לא ע"י המשתמש) - מחזיר את הפקודה הממתינה האחרונה
    (אם יש) עבור המחשב הזה, ומיד מנקה את הסיסמה מה-DB כדי לצמצם חשיפה.
    no-store חובה: זה endpoint שנבדק כל 5 דק' ל-Stop/Start/Uninstall מרחוק - תגובה ממטמון
    בקצה (CDN) תגרום לפקודות "לא להתקבל" בפועל אצל ה-agent, גם כשהן ממתינות ב-DB."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    check_auth(x_agent_token)
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT id, command, password, maintenance_minutes FROM commands WHERE host = %s AND status = 'pending' ORDER BY id ASC LIMIT 1",
        (host,),
    )
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE commands SET status = 'delivered', password = NULL, delivered_at = now() WHERE id = %s", (row["id"],))
        conn.commit()
    cur.close()
    conn.close()
    if not row:
        return {"command": None}
    return {"command": row["command"], "password": row["password"], "maintenance_minutes": row["maintenance_minutes"]}


@app.get("/api/stats")
def get_stats(x_session_token: Optional[str] = Header(default=None)):
    check_session(x_session_token)
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT count(*) FROM events")
    total_events = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM alerts WHERE severity IN ('Critical', 'High')")
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
        "Malware": {"audit_log_cleared", "new_service_installed", "malware_detected", "malware_blocked", "defender_protection_disabled"},
        "Tamper": {"agent_tamper_detected"},
    }
    heat = {cat: [0] * 6 for cat in categories}

    for row in recent:
        action, severity, hr = row
        bi = bucket_index(hr or 0)
        logs_series[bi] += 1
        if severity:
            alerts_series[bi] += 1
        if severity in ("High", "Critical"):
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
def investigate(event_id: int, x_session_token: Optional[str] = Header(default=None)):
    check_session(x_session_token)
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, ts as timestamp, user_name as user, action,
               COALESCE(host, source) as host, ip as source_ip, severity, score, description, lan_ip, wan_ip
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
               COALESCE(host, source) as host, ip as source_ip, severity, score, description, lan_ip, wan_ip
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
    """endpoint שממנו ה-agent המותקן על תחנות הקצה מושך גרסה מעודכנת של עצמו.
    חשוב: no-store מפורש - בלי זה Vercel/הרשת מגישים תגובה ישנה מהמטמון בקצה (CDN),
    וה-agent (ו-install.ps1 שמוריד מכאן כשאין send.ps1 מקומי) נשארים תקועים על גרסה ישנה
    לצמיתות, גם כשה-deploy עצמו הצליח והקובץ בפועל התעדכן."""
    path = os.path.join(os.path.dirname(__file__), "agent", "send.ps1")
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return PlainTextResponse(
            content,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
            },
        )
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@app.get("/api/nssm-download")
def nssm_download():
    """endpoint שממנו install.ps1 מוריד את nssm.exe אם הוא לא קיים מקומית -
    מגיש את הקובץ שכבר נמצא בפריסה (api/nssm.exe), כדי לא להסתמך על מקור חיצוני לא יציב."""
    path = os.path.join(os.path.dirname(__file__), "nssm.exe")
    try:
        with open(path, "rb") as f:
            data = f.read()
        return Response(content=data, media_type="application/octet-stream", headers={
            "Content-Disposition": 'attachment; filename="nssm.exe"'
        })
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
