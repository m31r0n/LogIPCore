# src/main.py

import os
import asyncio
import aiohttp
import csv
import logging
from collections import Counter
from tqdm import tqdm

# Importar módulos propios
from banner import show_banner
from config import load_config
from log_parser import parse_input, add_default_fields
from ip_analyzer import IPAnalyzer
from utils import is_internal_ip, print_status, get_country_from_ip

logging.basicConfig(
    filename='log_analysis.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


async def fetch_tor_nodes(session):
    """
    Consulta de forma asíncrona la lista de nodos TOR.
    """
    url = 'https://check.torproject.org/torbulkexitlist'
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                text = await response.text()
                return set(text.split('\n'))
            else:
                logging.error(f"Error al obtener nodos TOR: {response.status}")
                return set()
    except Exception as e:
        logging.error(f"Excepción al obtener nodos TOR: {e}")
        return set()


def simple_ip_analysis():
    """
    Opción 1: Analiza un archivo simple de IPs y genera un CSV con las IPs externas únicas
    y el resultado obtenido de las APIs.
    """
    file_path = input("Ingresa la ruta del archivo (TXT, CSV, LOG) con las IPs: ").strip()
    if not os.path.exists(file_path):
        print_status("El archivo no existe.", "error")
        return

    logs = parse_input(file_path)
    if not logs:
        print_status("No se encontraron registros.", "warning")
        return

    # Extraer IPs y filtrar solo las externas y únicas
    ips = [log.get('detected_ip') for log in logs if log.get('detected_ip')]
    unique_ips = {ip for ip in ips if ip and not is_internal_ip(ip)}

    print_status(f"Total de IPs encontradas: {len(ips)}", "info")
    print_status(f"Total de IPs únicas y externas: {len(unique_ips)}", "info")
    for ip in unique_ips:
        print(f" - {ip}")

    apis_input = input("Ingresa las APIs a utilizar (opciones: ipabuse, virustotal, criminalip, tor): ").strip().lower()
    selected_apis = [x.strip() for x in apis_input.split(',')] if apis_input else ["ipabuse"]

    async def async_analysis():
        async with aiohttp.ClientSession() as session:
            tor_nodes = await fetch_tor_nodes(session) if "tor" in selected_apis else set()
            analyzer = IPAnalyzer(session, selected_apis, tor_nodes)
            tasks = [asyncio.create_task(analyzer.analyze_ip(ip)) for ip in unique_ips]
            results = []
            for future in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Analizando IPs"):
                results.append(await future)
            return results

    analysis_results = asyncio.run(async_analysis())
    ip_analysis = {ip: result for ip, result in zip(unique_ips, analysis_results)}

    case_name = input("Ingresa el nombre del caso: ").strip()
    output_folder = os.path.join("data", "output")
    os.makedirs(output_folder, exist_ok=True)
    ip_analysis_file = os.path.join(output_folder, f'{case_name}_ip_analysis.csv')

    # Definir los encabezados que queremos en el CSV
    fieldnames = ['Analyzed_IP', 'ip', 'IP_Type', 'IPAbuse', 'VirusTotal', 'CriminalIP', 'TOR', 'MaliciousScore', 'Country']
    with open(ip_analysis_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, analysis in ip_analysis.items():
            row = {
                'Analyzed_IP': ip,
                'ip': ip,
                'IP_Type': 'External',
                'IPAbuse': analysis.get('IPAbuse', "N/A"),
                'VirusTotal': analysis.get('VirusTotal', "N/A"),
                'CriminalIP': analysis.get('CriminalIP', "N/A"),
                'TOR': analysis.get('TOR', "N/A"),
                'MaliciousScore': analysis.get('MaliciousScore', "N/A"),
                # Usamos geoip2 (via get_country_from_ip) para determinar el país
                'Country': get_country_from_ip(ip)
            }
            writer.writerow(row)
    print_status(f"Archivo de análisis generado: {ip_analysis_file}", "info")
    input("Presiona Enter para volver al menú principal...")


def logs_analysis():
    """
    Opción 2: Analiza ficheros o carpetas de logs.
    Para cada archivo, se genera un CSV parseado que incluye la línea completa,
    la IP extraída y, si se realiza el análisis API, se añaden las columnas:
    Analyzed_IP, API_Result y Country.
    Además, se genera un resumen global.
    """
    path = input("Ingresa la ruta del archivo o carpeta de logs: ").strip()
    if not os.path.exists(path):
        print_status("El archivo o carpeta no existe.", "error")
        return

    overall_ips = []
    valid_ext = {'.csv', '.txt', '.log'}
    file_list = []
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if os.path.splitext(file)[1].lower() in valid_ext:
                    file_list.append(os.path.join(root, file))
    else:
        file_list.append(path)

    for file_path in file_list:
        print_status(f"Procesando archivo: {file_path}", "info")
        logs = parse_input(file_path)
        if not logs:
            print_status(f"No se encontraron registros en {file_path}.", "warning")
            continue

        output_folder = os.path.join("data", "output")
        os.makedirs(output_folder, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(file_path))[0]

        # Se toman los keys de todos los registros para formar el header
        all_keys = set()
        for record in logs:
            all_keys.update(record.keys())

        # Se agrega manualmente las columnas que queremos y se remueve 'source_file'
        header = list(all_keys) + ['IP_Type', 'Analyzed_IP', 'API_Result', 'Country']
        if 'source_file' in header:
            header.remove('source_file')

        # Escribimos el CSV filtrando cada registro a las keys del header
        parsed_log_file = os.path.join(output_folder, f'{base_name}_parsed_log.csv')
        with open(parsed_log_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header)
            writer.writeheader()
            for record in logs:
                detected = record.get('detected_ip')
                record['IP_Type'] = 'Internal' if (detected and is_internal_ip(detected)) else ('External' if detected else 'N/A')
                record['Analyzed_IP'] = detected if detected else "N/A"
                record['API_Result'] = "N/A"
                record['Country'] = get_country_from_ip(detected) if detected else "N/A"

                # Filtrar las claves para escribir solo las definidas en header
                filtered_record = {key: record.get(key, "") for key in header}
                writer.writerow(filtered_record)

        print_status(f"Archivo parseado generado: {base_name}_parsed_log.csv", "info")

        # Extraer IPs para el resumen global y posible análisis API
        ips = [r.get('detected_ip') for r in logs if r.get('detected_ip')]
        external_ips = {ip for ip in ips if ip and not is_internal_ip(ip)}
        overall_ips.extend(ips)

        analyze_api = input(f"¿Deseas analizar las IPs externas de {file_path} mediante APIs? (s/n): ").strip().lower()
        if analyze_api == 's' and external_ips:
            apis_input = input("Ingresa las APIs a utilizar (opciones: ipabuse, virustotal, criminalip, tor): ").strip().lower()
            selected_apis = [x.strip() for x in apis_input.split(',')] if apis_input else ["ipabuse"]

            async def async_analysis():
                async with aiohttp.ClientSession() as session:
                    tor_nodes = await fetch_tor_nodes(session) if "tor" in selected_apis else set()
                    analyzer = IPAnalyzer(session, selected_apis, tor_nodes)
                    tasks = [asyncio.create_task(analyzer.analyze_ip(ip)) for ip in external_ips]
                    results = []
                    for future in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Analizando IPs"):
                        results.append(await future)
                    return results

            analysis_results = asyncio.run(async_analysis())
            api_results_map = {ip: result for ip, result in zip(external_ips, analysis_results)}

            # Actualizamos el CSV parseado añadiendo los datos API para cada registro con IP externa
            updated_records = []
            for record in logs:
                detected = record.get('detected_ip')
                if detected and not is_internal_ip(detected) and detected in api_results_map:
                    record["Analyzed_IP"] = detected
                    record["API_Result"] = api_results_map[detected].get("MaliciousScore", "N/A")
                    record["Country"] = api_results_map[detected].get("country", "N/A")
                updated_records.append(record)

            # Sobrescribimos el archivo parseado con los nuevos campos
            with open(parsed_log_file, 'w', newline='', encoding='utf-8') as csvfile:
                # Usamos el mismo header
                writer = csv.DictWriter(csvfile, fieldnames=header)
                writer.writeheader()
                for rec in updated_records:
                    filtered_rec = {key: rec.get(key, "") for key in header}
                    writer.writerow(filtered_rec)

            print_status(f"Archivo de análisis API actualizado: {base_name}_parsed_log.csv", "info")
        else:
            print_status(f"No se realizó análisis API para {file_path}.", "warning")

    # Resumen global
    total_ips = len(overall_ips)
    unique_ips = {ip for ip in overall_ips if ip}
    external_ips_global = {ip for ip in unique_ips if not is_internal_ip(ip)}
    ip_counts = Counter(overall_ips)
    top10 = ip_counts.most_common(10)
    summary_file = os.path.join(output_folder, "global_summary.txt")
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(f"Total de IPs encontradas: {total_ips}\n")
        f.write(f"Total de IPs únicas: {len(unique_ips)}\n")
        f.write(f"Total de IPs externas: {len(external_ips_global)}\n\n")
        f.write("Top 10 IPs:\n")
        for ip, count in top10:
            f.write(f"{ip}: {count}\n")

    print_status(f"Resumen global generado: {summary_file}", "info")
    input("Presiona Enter para volver al menú principal...")


def fortinet_logs_analysis():
    """
    Opción 3: Analiza ficheros o carpetas de logs Fortinet.
    Para cada archivo, se genera un CSV parseado que incluye:
      - Los campos extraídos (por ejemplo, date, time, srcip, etc.)
      - La línea completa en el campo "line" (si se conserva)
      - Una columna adicional "Connection_Status" que confirma si hubo conexión exitosa.
    """
    path = input("Ingresa la ruta del archivo o carpeta de logs Fortinet: ").strip()
    if not os.path.exists(path):
        print_status("El archivo o carpeta no existe.", "error")
        return

    file_list = []
    valid_ext = {'.csv', '.txt', '.log'}
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if os.path.splitext(file)[1].lower() in valid_ext:
                    file_list.append(os.path.join(root, file))
    else:
        file_list.append(path)

    # Importar la función de análisis para logs Fortinet
    from fortinet_analyzer import analyze_fortinet_log

    for file_path in file_list:
        print_status(f"Procesando archivo: {file_path}", "info")
        logs = parse_input(file_path)
        if not logs:
            print_status(f"No se encontraron registros en {file_path}.", "warning")
            continue

        output_folder = os.path.join("data", "output")
        os.makedirs(output_folder, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(file_path))[0]

        # Definir encabezados a partir de las claves encontradas en los registros
        all_keys = set()
        for record in logs:
            all_keys.update(record.keys())
        # Agregar la nueva columna y eliminar source_file si existe
        header = list(all_keys) + ['Connection_Status']
        if 'source_file' in header:
            header.remove('source_file')

        fortinet_csv_file = os.path.join(output_folder, f'{base_name}_fortinet_parsed.csv')
        with open(fortinet_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header)
            writer.writeheader()
            for record in logs:
                # Determinar el tipo de IP (si hay campo detected_ip)
                detected = record.get('detected_ip')
                record['IP_Type'] = 'Internal' if (detected and is_internal_ip(detected)) else ('External' if detected else 'N/A')
                # Llamar a la función para analizar el log Fortinet y determinar el estado de conexión
                record['Connection_Status'] = analyze_fortinet_log(record)
                # Filtrar solo las claves definidas en header para evitar errores
                filtered_record = {key: record.get(key, "") for key in header}
                writer.writerow(filtered_record)
        print_status(f"Archivo Fortinet parseado generado: {fortinet_csv_file}", "info")

    input("Presiona Enter para volver al menú principal...")


def menu():
    while True:
        print("\n===== Menú Principal de LogIPCore =====")
        print("1. Analizar archivo de IPs simples")
        print("2. Analizar archivos o carpeta de logs")
        print("3. Analizar logs Fortinet")
        print("4. Salir")
        opcion = input("Selecciona una opción: ").strip()
        if opcion == "1":
            simple_ip_analysis()
        elif opcion == "2":
            logs_analysis()
        elif opcion == "3":
            fortinet_logs_analysis()
        elif opcion == "4":
            print("Saliendo... ¡Hasta pronto!")
            break
        else:
            print("Opción inválida. Intenta nuevamente.")


def main():
    show_banner()        # Muestra el banner ASCII
    load_config()        # Carga configuración (por ejemplo, API keys) desde config.ini
    print("Bienvenido a LogIPCore - Analizador de IPs y Logs\n")
    menu()


if __name__ == "__main__":
    main()
