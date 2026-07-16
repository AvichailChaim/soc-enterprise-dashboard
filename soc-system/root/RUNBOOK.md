# Hayanuka SOC — Runbook

מסמך תפעולי לאחר עדכון הקוד (חיבור אמיתי בין ה-agent, ה-API וה-Dashboard). כל הקבצים שהוזכרו כאן נמצאים תחת `root/`.

## 0. דחוף — סיסמת DB חשופה

הקובץ `New Text Document.txt` בשורש הפרויקט מכיל את מחרוזת ההתחברות המלאה (כולל סיסמה) ל-Neon Postgres. אם התיקייה הזו מחוברת ל-GitHub:

1. ב-Neon: Reset password לסיסמת ה-DB.
2. עדכן את `DATABASE_URL` ב-Vercel -> Settings -> Environment Variables לערך החדש.
3. מחק את הקובץ מהריפו (ואם כבר הועלה בעבר — גם מהיסטוריית ה-git).

## 1. משתני סביבה נדרשים ב-Vercel

Settings -> Environment Variables בפרויקט:

| Key | ערך |
|---|---|
| `DATABASE_URL` | מחרוזת ההתחברות ל-Neon (אחרי ה-rotate בסעיף 0) |
| `AGENT_TOKEN` | מחרוזת סודית שתבחר בעצמך, לדוגמה `openssl rand -hex 24`. חייבת להיות זהה לטוקן שמוזרק ל-agent בסעיף 3. |

בלי `AGENT_TOKEN` מוגדר, ה-API ידלג על אימות (מצב פיתוח בלבד) — לא מומלץ בפרודקשן.

לאחר שינוי משתני סביבה יש לבצע Redeploy בוורסל כדי שהם ייכנסו לתוקף.

## 2. מה תוקן/נוסף בקוד

- **`api/index.py`** — עכשיו יוצר/משדרג סכימה אוטומטית (events + alerts), מריץ מנוע ניקוד וקורלציה (brute-force) על כל אירוע נכנס, ומחזיר endpoints אמיתיים: `/api/event` (POST), `/api/events`, `/api/alerts`, `/api/stats`, `/api/investigate/{id}`, `/api/agent-update`. יש גם אימות בסיסי דרך header `X-Agent-Token`.
- **`frontend/index.html`** — מחובר עכשיו ל-`/api/*` (לפני כן ניסה `/stats`/`/events` שלא היו קיימים, ולכן כל מה שהוצג היה נתונים קבועים בקוד). ה-KPIs, הגרף, ה-heatmap, ו-Top IPs/Users נטענים כעת מהשרת. נוסף כפתור **Investigate** בכל שורה שפותח פאנל חקירה (אירוע + אירועים קשורים לפי user/IP/host בחלון של 30 דקות). לחצני הסיידבר (Logs/Alerts/Threats) מסננים כעת את הטבלה בפועל.
- **`api/agent/send.ps1`** — מצביע לכתובת הפרודקשן ב-Vercel (לא לטאנל זמני), שולח header עם הטוקן, קורא Event IDs נוספים (ראה סעיף 4), ושומר על מנגנון ה-self-update (מושך גרסה חדשה מ-`/api/agent-update`).
- **`api/agent/install.ps1`** — מתקין את `send.ps1` כשירות Windows (NSSM), עם פרמטר `-AgentToken` שמזריק את הטוקן הנכון בזמן ההתקנה, ותיקון נתיב ל-`nssm.exe` (יחסי לתיקייה, לא נתיב קבוע).

## 3. הפצה למחשב בודד (בדיקה)

על תחנת קצה, כ-Administrator:

```powershell
cd "D:\Cyber\soc-system\root\api\agent"
.\install.ps1 -AgentToken "הטוקן-שהגדרת-ב-Vercel"
```

בדיקה: `C:\Program Files\Hayanuka_SIEM\debug.txt` אמור להראות "Agent Started" ו-"Sent: ...". בדשבורד (ה-URL של Vercel) אמור להופיע האירוע תוך כמה שניות.

## 4. הפצה לכל הארגון

כשהבדיקה על מכונה אחת עובדת:

- ארוז את `install.ps1` + `send.ps1` + `nssm.exe` (מ-`api/`) יחד.
- הפץ דרך GPO Startup Script / Intune / כלי RMM שיש לך בארגון, עם הפקודה מסעיף 3. הרצה ידנית מחשב-מחשב לא ריאלית בקנה מידה ארגוני.
- ודא ש-Windows Security auditing מופעל בכל המחשבים לאירועים הרלוונטיים (Logon/Logoff, Account Management, Object Access) — אחרת חלק מה-Event IDs לא ייווצרו בכלל.

## 5. חקירה (Investigation) בממשק

כל שורה בטבלה כוללת כפתור **Investigate** שפותח: פרטי האירוע המלאים, ה-severity/score, טכניקת MITRE משוערת, ואירועים קשורים (אותו משתמש/IP/host) בטווח של 30 דקות סביב האירוע. לחיצה על ה-KPI tiles או על IP/User ברשימות Top מסננת את הטבלה הראשית.

## 6. הרחבת הזיהוי (עוד Event IDs / חוקים)

נוספו כבר: 4740 (נעילת חשבון — brute force), 4648 (credentials מפורשים — lateral movement), 4672 (logon מנהלתי), 4697 + 7045 (התקנת שירות — persistence).

כדי להוסיף עוד:

1. ב-`api/agent/send.ps1`: הוסף את ה-Event ID ל-`$secIds` (או שאילתת log נפרדת אם זה log אחר), והוסף `case` תואם ב-`switch ($eventID)`.
2. ב-`api/index.py`: הוסף את ה-`action` החדש למילון `BASE_SCORES` (ניקוד + תיאור) ול-`MITRE_MAP` (טכניקה משוערת).
3. פרסם מחדש (git push -> Vercel redeploy). ה-agents הקיימים ימשכו את הגרסה החדשה של `send.ps1` אוטומטית דרך מנגנון ה-self-update (מחזור בדיקה כל ~100 שניות).

## 7. בדיקת המערכת בלי לגעת בלוגים אמיתיים

כדי לבדוק את הדשבורד/ההתראות בלי ליצור אירועי אבטחה אמיתיים, אפשר לשלוח אירוע מדומה ישירות ל-API:

```powershell
$body = @{ user="test.user"; action="login_failed"; source="TEST-PC"; ip="10.0.0.99" } | ConvertTo-Json
Invoke-RestMethod -Uri "https://soc-enterprise-dashboard-hayanuka.vercel.app/api/event" -Method Post -Body $body -ContentType "application/json" -Headers @{ "X-Agent-Token" = "הטוקן-שלך" }
```

שלח את זה 5+ פעמים ברצף עם אותו user/ip כדי לראות גם את זיהוי ה-brute-force מופעל.

לבדיקת ניסיון פריצה אמיתי (רק על מכונת מעבדה/טסט, לא פרודקשן): כמה נסיונות RDP/login כושלים מכוונים, יצירת משתמש טסט, או ניקוי Event Log — כל אלו כבר מכוסים וייצרו alert.

## 8. קבצים ישנים/מיותרים

`api/backend/*` (מנוע מקומי עם SQLite), `api/send.ps1`, `api/run.bat` הם גרסאות פיתוח מוקדמות שהוחלפו ע"י `api/index.py` המאוחד. אפשר להשאיר לעת עתה, אך מומלץ להסיר אחרי שווידאת שה-agent החדש עובד בייצור, כדי למנוע בלבול עתידי.
