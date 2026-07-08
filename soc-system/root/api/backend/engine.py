def analyze_event(e):
    score = 0
    description_parts = []

    # 1. ניסיון פתיחת קובץ ישיר ללא הרשאות במערכת (Access Denied)
    if e["action"] == "file_permission_denied":
        score += 55
        description_parts.append(f"Unauthorized local file access attempt blocked (Access Denied).")

    # 2. ניסיון גישה מרחוק לשיתוף קבצים עם סיסמה שגויה
    elif e["action"] == "network_file_access_failed":
        score += 65
        description_parts.append("Unauthorized network/file share access attempt with bad credentials.")

    # 3. ניסיון התחברות מקומי נכשל
    elif e["action"] == "login_failed":
        score += 40
        description_parts.append("Failed local login attempt.")

    # 4. יצירת משתמש חדש במערכת
    if e["action"] == "user_created":
        score += 60
        description_parts.append(f"New local user account '{e['user']}' was created.")

    # 5. מחיקת לוגים אקטיבית
    if e["action"] == "audit_log_cleared":
        score += 95
        description_parts.append("CRITICAL: Windows Security log was cleared!")

    # 6. בדיקת יוזר מנהלתי
    if "admin" in e["user"].lower() or "administrator" in e["user"].lower():
        score += 20
        description_parts.append("Target user has administrative keywords.")

    description = " | ".join(description_parts) if description_parts else "Normal system activity."

    if score >= 70:
        return {"alert": True, "severity": "High", "score": score, "description": description}
    elif score >= 40:
        return {"alert": True, "severity": "Medium", "score": score, "description": description}

    return {"alert": False, "score": score, "description": description}