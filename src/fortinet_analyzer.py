# src/fortinet_analyzer.py


def analyze_fortinet_log(record):
    """
    Analiza un registro de log de Fortinet y determina si la conexión fue exitosa.
    Retorna "Success", "Failure" o "Unknown" según tipo/subtipo del log.
    """
    log_type = record.get("type", "").lower()
    subtype = record.get("subtype", "").lower()
    status = record.get("status", "").lower()
    msg = record.get("msg", "").lower()
    logdesc = record.get("logdesc", "").lower()
    action = record.get("action", "").lower()

    # Traffic Logs
    if log_type == "traffic" and subtype == "forward":
        utmaction = record.get("utmaction", "").lower()
        if utmaction == "allow" or action == "accept":
            return "Success"
        return "Failure"

    # Traffic Local
    if log_type == "traffic" and subtype == "local":
        if action in ("accept", "allow"):
            return "Success"
        return "Failure"

    # VPN Events
    if log_type == "event" and subtype == "vpn":
        result = record.get("result", "").lower()
        if status == "success" and result == "ok":
            return "Success"
        if "tunnel-up" in action or "tunnel established" in msg:
            return "Success"
        return "Failure"

    # System Events
    if log_type == "event" and subtype == "system":
        if "login successful" in logdesc or "logged in successfully" in msg:
            return "Success"
        if "login failed" in logdesc or "authentication failure" in msg:
            return "Failure"
        return "Failure"

    # User Events
    if log_type == "event" and subtype == "user":
        if "authentication success" in logdesc or status == "success":
            return "Success"
        return "Failure"

    # Endpoint Events
    if log_type == "event" and subtype == "endpoint":
        if ("connection added" in logdesc or "connection closed" in logdesc) and status == "success":
            return "Success"
        return "Failure"

    # WAF/UTM Events
    if log_type == "utm":
        if action in ("pass", "allow"):
            return "Success"
        return "Failure"

    return "Unknown"
