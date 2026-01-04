from collections import Counter

ATTACK_HINTS = {
    "iam_key_created": "A new cloud access key was created, which can indicate credential abuse or persistence.",
    "suspicious_powershell": "Suspicious PowerShell execution may indicate attacker living-off-the-land techniques.",
    "impossible_travel": "A login from an unusual region may indicate stolen credentials or VPN misuse.",
    "c2_outbound": "Outbound traffic to suspicious infrastructure may indicate command-and-control activity.",
    "multiple_failed_logins": "Repeated failures may indicate brute force or password spraying.",
    "s3_public": "Public storage exposure is a common data leak misconfiguration."
}

NEXT_ACTIONS = {
    "iam_key_created": ["Disable the newly created key", "Rotate credentials for the affected identity", "Review CloudTrail for follow-on actions"],
    "suspicious_powershell": ["Isolate the endpoint", "Collect process tree and PowerShell transcript", "Hunt for similar commands across fleet"],
    "impossible_travel": ["Force password reset / MFA step-up", "Review recent sessions and token issuance", "Check device fingerprint changes"],
    "c2_outbound": ["Block destination IP/domain", "Inspect DNS logs for related domains", "Capture pcap if available"],
    "multiple_failed_logins": ["Enable temporary lockout / rate limit", "Check for sprayed accounts", "Review source IP reputation"],
    "s3_public": ["Revert bucket policy/ACL", "Scan access logs for downloads", "Check for sensitive objects exposure"],
}

def build_title(alerts: list[dict]) -> str:
    types = [a["alert_type"] for a in alerts]
    top = Counter(types).most_common(1)[0][0]
    user = next((a.get("user","") for a in alerts if a.get("user")), "")
    host = next((a.get("host","") for a in alerts if a.get("host")), "")
    parts = [top.replace("_", " ").title()]
    if user: parts.append(f"user={user}")
    if host: parts.append(f"host={host}")
    return " | ".join(parts)

def explain_incident(alerts: list[dict], severity: str, confidence: float, risk_score: float) -> str:
    types = [a["alert_type"] for a in alerts]
    sources = sorted({a["source"] for a in alerts})
    top_types = [t for t,_ in Counter(types).most_common(3)]

    bullets = []
    bullets.append(f"Incident severity: {severity.upper()} | risk score: {risk_score}/100 | confidence: {round(confidence,2)}")
    bullets.append(f"Signals observed from sources: {', '.join(sources)}")
    bullets.append("Key signals:")
    for t in top_types:
        hint = ATTACK_HINTS.get(t, "Suspicious activity detected that may require investigation.")
        bullets.append(f"- {t}: {hint}")

    # recommendations
    recs = []
    for t in top_types:
        recs.extend(NEXT_ACTIONS.get(t, []))
    # de-dup while preserving order
    seen = set()
    recs = [r for r in recs if not (r in seen or seen.add(r))]

    bullets.append("Recommended next actions (ranked):")
    for r in recs[:6]:
        bullets.append(f"- {r}")

    return "\n".join(bullets)
