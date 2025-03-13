# src/fortinet_analyzer.py

def analyze_fortinet_log(record):
    """
    Analiza un registro de log de Fortinet y determina si la conexión fue exitosa.
    Devuelve "Success" si se cumplen las condiciones según el tipo/subtipo del log, o "Failure" en caso contrario.
    """
    log_type = record.get("type", "").lower()
    subtype = record.get("subtype", "").lower()
    status = record.get("status", "").lower()
    msg = record.get("msg", "").lower()
    logdesc = record.get("logdesc", "").lower()

    # Traffic Logs: se evalúa el campo 'utmaction'
    if log_type == "traffic" and subtype == "forward":
        if record.get("utmaction", "").lower() == "allow":
            return "Success"
        else:
            return "Failure"

    # VPN Events
    if log_type == "event" and subtype == "vpn":
        if status == "success" and record.get("result", "").lower() == "ok":
            return "Success"
        else:
            return "Failure"

    # System Events: ejemplo, login exitoso
    if log_type == "event" and subtype == "system":
        if "login successful" in logdesc or "logged in successfully" in msg:
            return "Success"
        else:
            return "Failure"

    # User Events
    if log_type == "event" and subtype == "user":
        if "authentication success" in logdesc or status == "success":
            return "Success"
        else:
            return "Failure"

    # Endpoint Events
    if log_type == "event" and subtype == "endpoint":
        if ("connection added" in logdesc or "connection closed" in logdesc) and status == "success":
            return "Success"
        else:
            return "Failure"

    return "Unknown"
