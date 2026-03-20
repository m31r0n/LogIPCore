# src/log_parser.py
"""
Parser multi-formato con auto-detección.
Formatos soportados: JSON lines, CEF, Syslog, Apache/Nginx, Key=Value, CSV, texto plano.
"""

import os
import re
import csv
import json

# ─── Regex ──────────────────────────────────────────────────────

IPV4_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
IPV6_RE = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b')
PAIR_RE = re.compile(r'(\w+)=(".*?"|\S+)')

SYSLOG_RE = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)'
)

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

CEF_RE = re.compile(
    r'^CEF:\s*(?P<version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|'
    r'(?P<dev_version>[^|]*)\|(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|'
    r'(?P<severity>[^|]*)\|(?P<extensions>.*)'
)

# Nombres comunes de campos IP en JSON/CSV
IP_FIELD_NAMES = {
    'ip', 'src_ip', 'srcip', 'source_ip', 'src', 'source',
    'dst_ip', 'dstip', 'destination_ip', 'dst', 'destination',
    'client_ip', 'clientip', 'remote_ip', 'remoteip', 'remote_addr',
    'peer_ip', 'host_ip', 'attacker_ip', 'ip_address', 'ipaddress',
    'remip', 'sourceip', 'destip', 'sender_ip', 'origin_ip',
}


# ─── Auto-detección ────────────────────────────────────────────

def detect_format(file_path):
    """Auto-detecta el formato del archivo leyendo las primeras líneas."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = []
        for _ in range(10):
            line = f.readline()
            if not line:
                break
            lines.append(line.strip())

    if not lines:
        return 'text'

    first = lines[0]

    # JSON lines
    if first.startswith('{'):
        try:
            json.loads(first)
            return 'json'
        except json.JSONDecodeError:
            pass

    # CEF
    if first.startswith('CEF:'):
        return 'cef'

    # Syslog
    if SYSLOG_RE.match(first):
        return 'syslog'

    # Apache/Nginx combined
    if APACHE_RE.match(first):
        return 'apache'

    # Key=Value (al menos 2 pares en la línea)
    if len(PAIR_RE.findall(first)) >= 2:
        return 'kv'

    # CSV (intenta sniff)
    if ',' in first or ';' in first or '\t' in first:
        try:
            csv.Sniffer().sniff('\n'.join(lines[:5]))
            return 'csv'
        except csv.Error:
            pass

    return 'text'


# ─── Extracción de IPs ─────────────────────────────────────────

def extract_ip(text):
    """Extrae la primera IP (v4 o v6) de un texto."""
    m = IPV4_RE.search(text)
    if m:
        return m.group()
    m = IPV6_RE.search(text)
    if m:
        return m.group()
    return None


def extract_all_ips(text):
    """Extrae todas las IPs de un texto."""
    return IPV4_RE.findall(text) + IPV6_RE.findall(text)


def find_ip_in_dict(d):
    """Busca una IP en campos conocidos de un diccionario."""
    for key in IP_FIELD_NAMES:
        val = d.get(key) or d.get(key.upper()) or d.get(key.title())
        if val and IPV4_RE.match(str(val)):
            return str(val)
    # Fallback: buscar en todos los valores
    for val in d.values():
        if isinstance(val, str):
            ip = extract_ip(val)
            if ip:
                return ip
    return None


# ─── Parsers por formato ───────────────────────────────────────

def parse_json_lines(file_path):
    """Parser para archivos JSON lines (un objeto JSON por línea)."""
    results = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    continue
                # Flatten nested dicts one level
                flat = {}
                for k, v in record.items():
                    if isinstance(v, dict):
                        for k2, v2 in v.items():
                            flat[f"{k}_{k2}"] = v2
                    else:
                        flat[k] = v
                flat['detected_ip'] = find_ip_in_dict(flat)
                flat['line'] = line
                flat['_format'] = 'json'
                results.append(flat)
            except json.JSONDecodeError:
                continue
    return results


def parse_cef(file_path):
    """Parser para Common Event Format (CEF)."""
    results = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = CEF_RE.match(line)
            if not m:
                continue
            record = {
                'cef_vendor': m.group('vendor'),
                'cef_product': m.group('product'),
                'cef_name': m.group('name'),
                'cef_severity': m.group('severity'),
            }
            # Parse extensions (key=value pairs)
            ext = m.group('extensions')
            for km in PAIR_RE.finditer(ext):
                key, val = km.group(1), km.group(2)
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                record[key] = val
            record['detected_ip'] = (
                record.get('src') or record.get('dst') or
                record.get('sourceAddress') or record.get('destinationAddress') or
                find_ip_in_dict(record)
            )
            record['line'] = line
            record['_format'] = 'cef'
            results.append(record)
    return results


def parse_syslog(file_path):
    """Parser para syslog BSD (RFC 3164)."""
    results = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = SYSLOG_RE.match(line)
            if m:
                record = {
                    'timestamp': m.group('timestamp'),
                    'hostname': m.group('hostname'),
                    'process': m.group('process'),
                    'pid': m.group('pid') or '',
                    'message': m.group('message'),
                }
            else:
                record = {'message': line}
            record['detected_ip'] = extract_ip(record.get('message', line))
            record['line'] = line
            record['_format'] = 'syslog'
            results.append(record)
    return results


def parse_apache(file_path):
    """Parser para Apache/Nginx combined log format."""
    results = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = APACHE_RE.match(line)
            if m:
                record = {
                    'detected_ip': m.group('ip'),
                    'user': m.group('user'),
                    'timestamp': m.group('timestamp'),
                    'method': m.group('method'),
                    'path': m.group('path'),
                    'status': m.group('status'),
                    'size': m.group('size'),
                    'referer': (m.group('referer') or '') if m.lastindex >= 7 else '',
                    'user_agent': (m.group('user_agent') or '') if m.lastindex >= 8 else '',
                }
            else:
                record = {'detected_ip': extract_ip(line), 'message': line}
            record['line'] = line
            record['_format'] = 'apache'
            results.append(record)
    return results


def parse_kv(file_path):
    """Parser para líneas con pares clave=valor (Fortinet, etc.)."""
    results = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = {}
            for key, val in PAIR_RE.findall(line):
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                record[key] = val
            record['detected_ip'] = (
                record.get('remip') or record.get('srcip') or
                record.get('src') or record.get('sourceip') or
                extract_ip(line)
            )
            record['line'] = line
            record['_format'] = 'kv'
            results.append(record)
    return results


def parse_csv_file(file_path):
    """Parser para archivos CSV con auto-detección de delimitador."""
    results = []
    with open(file_path, 'r', newline='', encoding='utf-8', errors='ignore') as f:
        try:
            dialect = csv.Sniffer().sniff(f.read(4096))
        except csv.Error:
            dialect = csv.excel
        f.seek(0)
        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            # Si hay columna 'log', parsear su contenido
            if 'log' in row and row['log']:
                for key, val in PAIR_RE.findall(row['log']):
                    if val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                    row[key] = val
            row['detected_ip'] = find_ip_in_dict(row) or extract_ip(str(row))
            row['_format'] = 'csv'
            results.append(row)
    return results


def parse_text(file_path):
    """Parser fallback: extrae IPs de cada línea."""
    results = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ip = extract_ip(line)
            results.append({
                'detected_ip': ip,
                'line': line,
                '_format': 'text',
            })
    return results


# ─── Dispatch ───────────────────────────────────────────────────

PARSERS = {
    'json': parse_json_lines,
    'cef': parse_cef,
    'syslog': parse_syslog,
    'apache': parse_apache,
    'kv': parse_kv,
    'csv': parse_csv_file,
    'text': parse_text,
}


def parse_file(file_path):
    """Detecta formato y parsea un archivo individual."""
    fmt = detect_format(file_path)
    parser = PARSERS.get(fmt, parse_text)
    return parser(file_path), fmt


def parse_input(path):
    """
    Punto de entrada principal.
    Acepta archivo o directorio. Retorna lista de records.
    """
    valid_ext = {'.csv', '.txt', '.log', '.json', '.jsonl', '.cef', '.evtx'}
    results = []

    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                if os.path.splitext(f)[1].lower() in valid_ext:
                    records, _ = parse_file(os.path.join(root, f))
                    results.extend(records)
    else:
        records, _ = parse_file(path)
        results.extend(records)

    return results


def add_default_fields(row, selected_apis):
    """Agrega campos de análisis con valor 'N/A' si no existen."""
    for key in ['IPAbuse', 'VirusTotal', 'CriminalIP', 'TOR', 'MaliciousScore']:
        if key not in row:
            row[key] = 'N/A'
    return row
