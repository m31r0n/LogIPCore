# src/utils.py
import ipaddress
from colorama import Fore

def is_ip(ip_str):
    """Verifica si una cadena es una dirección IP válida."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_internal_ip(ip):
    """Determina si una IP es interna (privada)."""
    try:
        ip_addr = ipaddress.ip_address(ip)
        return ip_addr.is_private
    except ValueError:
        return False

def print_status(message, status="info"):
    """Imprime mensajes en consola con colores según el tipo de mensaje."""
    if status == "info":
        print(Fore.GREEN + message)
    elif status == "warning":
        print(Fore.YELLOW + message)
    elif status == "error":
        print(Fore.RED + message)
    else:
        print(message)
# src/utils.py (agregar al final del archivo)

def get_country_from_ip(ip, db_path="data/GeoLite2-Country.mmdb"):
    try:
        import geoip2.database
        reader = geoip2.database.Reader(db_path)
        response = reader.country(ip)
        reader.close()
        return response.country.name if response.country.name else "N/A"
    except Exception as e:
        print(f"Error al obtener país para IP {ip}: {e}")
        return "N/A"
