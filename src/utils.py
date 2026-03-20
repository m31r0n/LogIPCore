# src/utils.py
import os
import ipaddress
from colorama import Fore, Style

_geoip_reader = None


def clean_path(path_str):
    """Limpia rutas: quita comillas, espacios, normaliza separadores."""
    if not path_str:
        return ""
    return os.path.normpath(path_str.strip().strip('"').strip("'").strip())


def ask_path(prompt):
    """Solicita ruta con validación y limpieza automática."""
    while True:
        raw = input(f"  {prompt}").strip()
        if not raw:
            continue
        path = clean_path(raw)
        if os.path.exists(path):
            return path
        print(f"  {Fore.RED}Ruta no encontrada: {path}{Style.RESET_ALL}")
        if input("  Reintentar? (s/n): ").strip().lower() != 's':
            return None


def select_apis():
    """Selección de APIs. Enter = todas."""
    print(f"\n  {Fore.CYAN}APIs:{Style.RESET_ALL} [1]AbuseIPDB [2]VirusTotal [3]CriminalIP [4]TOR [A]Todas")
    sel = input(f"  Selecciona (Enter=todas): ").strip().lower()

    api_map = {'1': 'ipabuse', '2': 'virustotal', '3': 'criminalip', '4': 'tor'}

    if not sel or 'a' in sel:
        return list(api_map.values())

    selected = [api_map[c.strip()] for c in sel.split(',') if c.strip() in api_map]
    return selected if selected else list(api_map.values())


def is_internal_ip(ip):
    """Determina si una IP es privada."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def print_status(msg, status="info"):
    colors = {"info": Fore.GREEN, "warning": Fore.YELLOW, "error": Fore.RED}
    print(f"  {colors.get(status, '')}{msg}{Style.RESET_ALL}")


def get_country_from_ip(ip, db_path=None):
    """País completo (nombre) desde GeoLite2."""
    global _geoip_reader
    if not ip:
        return "N/A"
    if db_path is None:
        from pathlib import Path
        db_path = str(Path(__file__).parent.parent / 'data' / 'GeoLite2-Country.mmdb')
    try:
        if _geoip_reader is None:
            import geoip2.database
            _geoip_reader = geoip2.database.Reader(db_path)
        resp = _geoip_reader.country(ip)
        return resp.country.name or "N/A"
    except Exception:
        return "N/A"
