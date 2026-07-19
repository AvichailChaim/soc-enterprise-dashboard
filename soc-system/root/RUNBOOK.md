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

בדיקה: `C:\Hayanuka_SIEM\debug.txt` אמור להראות "Agent Started" ו-"Sent: ...". בדשבורד (ה-URL של Vercel) אמור להופיע האירוע תוך כמה שניות.

### 3.1 חשוב — בלי זה חלק מהאירועים לא ייווצרו בכלל

Windows לא רושם כברירת מחדל את כל ה-Event IDs שה-agent מחפש. חלקם דורשים הפעלת Advanced Audit Policy מפורשת, ואחד מהם (4663 — ניסיון פתיחת קובץ ללא הרשאה) דורש גם הגדרת Auditing על התיקייה/קובץ הספציפיים (SACL), לא רק מדיניות כללית.

**זה כבר אוטומטי:** `install.ps1` עכשיו מפעיל את ה-audit policies הנדרשות בעצמו בכל התקנה (שלב 0), אז אין צורך להריץ את זה בנפרד לכל מחשב — זו אותה פעולה אחת שכבר עושים כשמתקינים את ה-agent.

**זו הגדרה מקומית לכל מחשב.** אם יש לך Active Directory domain, אפשר במקום זה להגדיר את אותן תת-קטגוריות פעם אחת ב-GPO (Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration), משויך ל-OU של כל מחשבי הארגון — כך זה חל אוטומטית על הכל בלי לגעת בכל מחשב בנפרד, וגם בלי תלות ב-`install.ps1`.

בשביל 4663 ספציפית (ניסיון פתיחת קובץ שנדחה) — צריך גם להוסיף Auditing entry על התיקיות הרגישות שרוצים לפקח עליהן: Properties -> Security -> Advanced -> Auditing -> Add -> Principal: Everyone -> Type: Fail -> Basic permissions: Read/Write/Delete. זה ספציפי לכל תיקייה/ארגון ולכן נשאר צעד ידני; אם יש לך רשימת תיקיות קבועה שרלוונטית לכל המחשבים (למשל תיקיות שיתוף רגישות), אפשר להוסיף גם את זה ל-`install.ps1` עם `icacls` — תגיד לי אם תרצה.

## 4. הפצה לכל הארגון

כשהבדיקה על מכונה אחת עובדת:

- ארוז את `install.ps1` + `send.ps1` + `nssm.exe` (מ-`api/`) יחד.
- הפץ דרך GPO Startup Script / Intune / כלי RMM שיש לך בארגון, עם הפקודה מסעיף 3. הרצה ידנית מחשב-מחשב לא ריאלית בקנה מידה ארגוני.
- ודא ש-Windows Security auditing מופעל בכל המחשבים לאירועים הרלוונטיים (Logon/Logoff, Account Management, Object Access) — אחרת חלק מה-Event IDs לא ייווצרו בכלל.

## 5. חקירה (Investigation) בממשק

כל שורה בטבלה כוללת כפתור **Investigate** שפותח: פרטי האירוע המלאים, ה-severity/score, טכניקת MITRE משוערת, ואירועים קשורים (אותו משתמש/IP/host) בטווח של 30 דקות סביב האירוע. לחיצה על ה-KPI tiles או על IP/User ברשימות Top מסננת את הטבלה הראשית.

## 6. הרחבת הזיהוי (עוד Event IDs / חוקים)

נוספו כבר:

- 4740 (נעילת חשבון), 4648 (credentials מפורשים — lateral movement), 4672 (logon מנהלתי), 4697 + 7045 (התקנת שירות — persistence).
- **יותר מניסיון כושל אחד** — כל כשלון login נוסף מאותו user/IP תוך 10 דקות מעלה ניקוד (לא מחכה ל-5 כשלונות).
- **ניסיונות מקבילים/תוך שניות** — 3+ כשלונות login (מכל user/IP) תוך 3 שניות מסומן כהתקפה ממוכנת אפשרית (password spraying).
- **גישה חוזרת שנדחתה** — 3+ ניסיונות `file_permission_denied`/`network_file_access_failed` מאותו משתמש תוך 2 דקות מסומן כסריקה/פריצה אפשרית.
- **Windows Defender** — האג'נט קורא גם את ה-log של Defender: זיהוי תוכנה זדונית/כופרה (1116), חסימה בפועל (1117), וכיבוי הגנה בזמן אמת (5001/5010/5012 — סימן חזק לניסיון תקיפה שמנטרל את ה-AV לפני שהוא פועל).

**חשוב לגבי פישינג:** האג'נט מבוסס Windows Event Log מקומי, ולכן לא יכול לזהות פישינג במייל או בדפדפן — זה דורש אינטגרציה נפרדת (Microsoft Defender for Office 365 / Microsoft Graph Security API, אם יש לך M365). אם זה רלוונטי אצלך, תגיד לי ונבנה את זה כתוסף נפרד.

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

## 9. תקלות ידועות — השירות עולה ל-Paused ולא רץ

היו שני גורמים שונים שגרמו לאותו תסמין (`Hayanuka_SIEM_Agent` עולה ל-Paused, ב-Event Viewer רואים "ran for less than 15000 milliseconds" עם קוד יציאה סינתטי כמו `4294770688`):

### 9.1 הבאג האמיתי (תוקן) — רווח בנתיב ("Program Files") שבר את ה-quoting

זו הייתה הסיבה המרכזית, וקרתה גם על מחשבים בלי שום אנטי-וירוס. תיקיית ההתקנה המקורית הייתה `C:\Program Files\Hayanuka_SIEM` — הרווח במילה "Program Files" גרם לכך שכש-nssm הפעיל את powershell.exe עם `-File C:\Program Files\Hayanuka_SIEM\send.ps1`, הפרמטר `-File` קיבל בפועל רק `C:\Program` (מחרוזת נחתכה ברווח), ו-powershell.exe נכשל ויצא כמעט מיידית, בלי להגיע אפילו לשורה הראשונה של הסקריפט (ולכן `debug.txt` לא נוצר בכלל).

**איך אובחן:** `nssm get Hayanuka_SIEM_Agent AppParameters` הראה את הנתיב בלי מרכאות מסביבו.

**התיקון:**
1. תיקיית ההתקנה שונתה ל-`C:\Hayanuka_SIEM` (בלי רווח בנתיב) — גם ב-`install.ps1` וגם ב-`send.ps1`.
2. `install.ps1` כבר לא מעביר את כל שורת הפקודה כמחרוזת אחת ל-`nssm install`; במקום זה, `Application` ו-`AppParameters` נקבעים בקריאות `nssm set` נפרדות, שמטפלות נכון ב-quoting גם אם יש רווחים בנתיב.

מי שכבר התקין עם הגרסה הישנה: להריץ ניקוי מלא (סעיף 3 למטה) ואז להתקין מחדש עם `install.ps1` המעודכן — הלוגים יעברו אוטומטית לנתיב החדש `C:\Hayanuka_SIEM\debug.txt`.

### 9.2 גורם אפשרי נוסף — Trend Micro Apex One / EDR

בנפרד מהבאג הנ"ל, על מחשבים עם **Trend Micro Apex One** מותקן (מופיע ב-Event Viewer, source `SecurityCenter`) יש סיכוי אמיתי שה-EDR יזהה את ה-agent כהתנהגות חשודה (תהליך שקורא Security log, שולח החוצה ל-HTTPS כל 10 שניות, ומחליף את הקובץ שלו) ויחסל אותו. הוסר `-WindowStyle Hidden` מהפעלת הסקריפט כדי להקטין את הסיכוי לזה. אם עדיין קורה: להוסיף Exclusion ב-Trend Micro (מקומי או ב-Apex Central) לנתיב `C:\Hayanuka_SIEM\send.ps1`, תחת Behavior Monitoring Exception List (ואולי גם Predictive Machine Learning), ואז Deploy של המדיניות.

**החלטה נוכחית:** ה-agent מופץ בינתיים רק על מחשבים בלי Trend Micro. עם התיקון בסעיף 9.1, סביר שהרבה ממה שנראה כמו "בעיית Trend Micro" בפועל היה הבאג של הרווח בנתיב — כדאי לנסות שוב גם על מחשבים עם Trend Micro אחרי התיקון, לפני שמניחים שזה עדיין חסום.
