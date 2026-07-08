import os
import psycopg2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# פונקציית עזר להתחברות ל-DB
def get_db_connection():
    # ה-DATABASE_URL יוגדר ב-Vercel ב-Settings -> Environment Variables
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    return conn

class Event(BaseModel):
    user: str
    action: str
    source: str
    ip: str

@app.post("/api/event")
def create_event(e: Event):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO events (user_name, action, source, ip) VALUES (%s, %s, %s, %s)",
            (e.user, e.action, e.source, e.ip)
        )
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/events")
def get_events():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY id DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {"data": rows}