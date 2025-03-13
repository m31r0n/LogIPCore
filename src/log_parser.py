# src/log_parser.py
import os
import re
import csv

PAIR_REGEX = re.compile(r'(\w+)=(".*?"|\S+)')
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

def find_ip_column(headers, rows):
    """
    Determina la columna que contiene direcciones IP:
      - Busca en los headers alguna columna con 'ip'.
      - Si no se encuentra, analiza el contenido de cada columna.
    """
    candidate_col = None
    if headers:
        ip_like_headers = [h for h in headers if 'ip' in h.lower()]
        if len(ip_like_headers) == 1:
            candidate_col = headers.index(ip_like_headers[0])
        elif len(ip_like_headers) > 1:
            best_count = 0
            for h in ip_like_headers:
                col_idx = headers.index(h)
                count = sum(1 for r in rows if len(r) > col_idx and IP_REGEX.search(r[col_idx]))
                if count > best_count:
                    best_count = count
                    candidate_col = col_idx
    if candidate_col is None and rows:
        best_count = 0
        for col_idx in range(len(rows[0])):
            count = sum(1 for r in rows if IP_REGEX.search(r[col_idx]))
            if count > best_count:
                best_count = count
                candidate_col = col_idx
    return candidate_col

def parse_csv(file_path):
    results = []
    with open(file_path, 'r', newline='', encoding='utf-8', errors='ignore') as f:
        try:
            dialect = csv.Sniffer().sniff(f.read(2048))
            f.seek(0)
        except csv.Error:
            dialect = csv.excel
            dialect.delimiter = ','
        f.seek(0)
        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            # Si existe una columna 'log', procesarla:
            if 'log' in row:
                log_line = row['log']
                matches = PAIR_REGEX.findall(log_line)
                for key, value in matches:
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    row[key] = value
                # Si no se extrajo detected_ip, se asigna usando 'remip' o se busca una IP en la línea
                if 'detected_ip' not in row:
                    row["detected_ip"] = row.get("remip") or (IP_REGEX.findall(log_line)[0] if IP_REGEX.findall(log_line) else None)
            else:
                # Para archivos CSV que ya tengan las columnas separadas, opcionalmente se puede asignar detected_ip
                if 'detected_ip' not in row:
                    row["detected_ip"] = None
            results.append(row)
    return results

def parse_text_file(file_path):
    """
    Parsea un archivo .txt o .log línea por línea, extrayendo pares clave=valor.
    Cada línea se convierte en un diccionario con las claves extraídas.
    Se agrega el campo 'detected_ip' utilizando, por ejemplo, el valor de 'remip'
    o buscando una IP en la línea.
    """
    results = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Extraer todos los pares clave=valor
            matches = PAIR_REGEX.findall(line)
            record = {}
            for key, value in matches:
                # Quitar comillas si existen
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                record[key] = value
            # Asignar detected_ip; si existe la clave 'remip' se usa, sino se busca la primera IP en la línea
            detected_ip = record.get("remip")
            if not detected_ip:
                ips = IP_REGEX.findall(line)
                detected_ip = ips[0] if ips else None
            record["detected_ip"] = detected_ip
            # También conservar la línea completa si es necesario
            record["line"] = line
            results.append(record)
    return results

def parse_input(path):
    """
    Si 'path' es un archivo, lo procesa directamente; si es un directorio,
    recorre los archivos compatibles (.csv, .txt, .log) y concatena los resultados.
    """
    logs = []
    valid_extensions = {'.csv', '.txt', '.log'}
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if os.path.splitext(file)[1].lower() in valid_extensions:
                    full_path = os.path.join(root, file)
                    if os.path.splitext(file)[1].lower() == '.csv':
                        logs.extend(parse_csv(full_path))
                    else:
                        logs.extend(parse_text_file(full_path))
    else:
        ext = os.path.splitext(path)[1].lower()
        if ext == '.csv':
            logs = parse_csv(path)
        else:
            logs = parse_text_file(path)
    return logs

def add_default_fields(row, selected_apis):
    """Agrega campos de análisis con valor 'N/A' si no se han completado."""
    for key in ['IPAbuse', 'VirusTotal', 'CriminalIP', 'TOR', 'MaliciousScore']:
        if key not in row:
            row[key] = 'N/A'
    return row

