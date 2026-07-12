def analyze_event(e):
    score = 0
    description_parts = []

    # לוגיקת הניתוח שלך
    if e["action"] == "file_permission_denied":
        score += 55
        description_parts.append("Unauthorized local file access attempt blocked.")
    elif e["action"] == "network_file_access_failed":
        score += 65
        description_parts.append("Unauthorized network access attempt.")
    elif e["action"] == "login_failed":
        score += 40
        description_parts.append("Failed local login attempt.")
    
    if e["action"] == "user_created":
        score += 60
        description_parts.append(f"New local user account '{e['user']}' created.")
    
    if e["action"] == "audit_log_cleared":
        score += 95
        description_parts.append("CRITICAL: Windows Security log was cleared!")

    if "admin" in e["user"].lower():
        score += 20
        description_parts.append("Target user has administrative keywords.")

    description = " | ".join(description_parts) if description_parts else "Normal system activity."

    if score >= 70:
        return {"alert": True, "severity": "High", "score": score, "description": description}
    elif score >= 40:
        return {"alert": True, "severity": "Medium", "score": score, "description": description}

    return {"alert": False, "severity": "Low", "score": score, "description": description}
