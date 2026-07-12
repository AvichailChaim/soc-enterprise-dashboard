from http.server import BaseHTTPRequestHandler
import json
import os
import psycopg2
from engine import analyze_event

# חיבור לבסיס הנתונים Neon
DATABASE_URL = os.environ.get("DATABASE_URL")

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        event = json.loads(post_data)

        # ניתוח האירוע בעזרת ה-Engine שלך
        analysis = analyze_event(event)

        # שמירה ב-Neon
        try:
            conn = psycopg2.connect(DATABASE_URL)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO logs (action, user_name, severity, score, description) VALUES (%s, %s, %s, %s, %s)",
                (event["action"], event["user"], analysis.get("severity", "Low"), analysis["score"], analysis["description"])
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"Database error: {e}")

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "processed", "alert": analysis["alert"]}).encode())
