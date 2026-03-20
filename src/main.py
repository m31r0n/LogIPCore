# src/main.py

import os
import asyncio
import aiohttp
import csv
import logging
from collections import Counter
from tqdm import tqdm
from colorama import Fore, Style, init as colorama_init

try:
    from src.banner import show_banner
    from src.config import load_config, get_output_folder
    from src.log_parser import parse_input
    from src.ip_analyzer import IPAnalyzer
    from src.fortinet_analyzer import analyze_fortinet_log
    from src.report import generate_xlsx, generate_html
    from src.utils import (
        is_internal_ip, print_status, get_country_from_ip,
        ask_path, select_apis,
    )
except ImportError:
    from banner import show_banner
    from config import load_config, get_output_folder
    from log_parser import parse_input
    from ip_analyzer import IPAnalyzer
    from fortinet_analyzer import analyze_fortinet_log
    from report import generate_xlsx, generate_html
    from utils import (
        is_internal_ip, print_status, get_country_from_ip,
        ask_path, select_apis,
    )

colorama_init(autoreset=True)
logging.basicConfig(filename='log_analysis.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Cache global: evita reanalizar IPs ya consultadas
_ip_cache = {}


# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

async def fetch_tor_nodes(session):
    """Descarga la lista de nodos de salida TOR."""
    try:
        async with session.get('https://check.torproject.org/torbulkexitlist', timeout=15) as r:
            if r.status == 200:
                return set(line.strip() for line in (await r.text()).split('\n') if line.strip())
    except Exception as e:
        logging.error(f"Error obteniendo nodos TOR: {e}")
    return set()


async def run_analysis(ips, selected_apis):
    """Ejecuta análisis async con cache de IPs."""
    global _ip_cache

    # Separar IPs ya cacheadas de las nuevas
    to_analyze = [ip for ip in ips if ip not in _ip_cache]
    cached = {ip: _ip_cache[ip] for ip in ips if ip in _ip_cache}

    if cached:
        print_status(f"{len(cached)} IPs recuperadas de cache, {len(to_analyze)} nuevas", "info")

    if to_analyze:
        async with aiohttp.ClientSession() as session:
            tor_nodes = await fetch_tor_nodes(session) if "tor" in selected_apis else set()
            analyzer = IPAnalyzer(session, selected_apis, tor_nodes)

            tasks = {ip: asyncio.create_task(analyzer.analyze_ip(ip)) for ip in to_analyze}
            for future in tqdm(asyncio.as_completed(list(tasks.values())),
                               total=len(tasks), desc="  Analizando"):
                result = await future
                ip = result["ip"]
                result["country_name"] = get_country_from_ip(ip)
                _ip_cache[ip] = result

    # Devolver todos los resultados en orden
    return [_ip_cache.get(ip, {"ip": ip}) for ip in ips]


def enrich_country(results_list):
    """Asegura que cada resultado tenga country_name."""
    for r in results_list:
        if "country_name" not in r or r["country_name"] == "N/A":
            r["country_name"] = get_country_from_ip(r["ip"])
    return results_list


# ═══════════════════════════════════════════════════════════════
#  Opción 1: Análisis de IPs
# ═══════════════════════════════════════════════════════════════

def simple_ip_analysis():
    print(f"\n  {Fore.CYAN}── Análisis de IPs ──{Style.RESET_ALL}")

    file_path = ask_path("Ruta del archivo de IPs: ")
    if not file_path:
        return

    logs = parse_input(file_path)
    if not logs:
        print_status("Sin registros.", "warning")
        return

    ips = [l.get('detected_ip') for l in logs if l.get('detected_ip')]
    unique_external = sorted({ip for ip in ips if ip and not is_internal_ip(ip)})

    print_status(f"IPs encontradas: {len(ips)} total, {len(unique_external)} externas únicas", "info")
    if not unique_external:
        print_status("No hay IPs externas.", "warning")
        return

    selected_apis = select_apis()
    results = asyncio.run(run_analysis(unique_external, selected_apis))
    results = enrich_country(results)

    # Nombre del caso
    case_name = input("  Nombre del caso: ").strip() or "analysis"
    output_folder = get_output_folder()

    # Generar reportes
    xlsx_path = generate_xlsx(results, case_name, output_folder)
    html_path = generate_html(results, case_name, output_folder)

    print_status(f"XLSX: {xlsx_path}", "info")
    print_status(f"HTML: {html_path}", "info")
    _print_quick_summary(results)

    input(f"\n  {Fore.CYAN}Enter para continuar...{Style.RESET_ALL}")


# ═══════════════════════════════════════════════════════════════
#  Opción 2: Análisis de logs
# ═══════════════════════════════════════════════════════════════

def logs_analysis():
    print(f"\n  {Fore.CYAN}── Análisis de Logs ──{Style.RESET_ALL}")

    path = ask_path("Ruta del archivo o carpeta de logs: ")
    if not path:
        return

    file_list = _collect_files(path)
    if not file_list:
        print_status("Sin archivos válidos.", "warning")
        return

    output_folder = get_output_folder()
    overall_ips = []

    for file_path in file_list:
        print_status(f"Procesando: {os.path.basename(file_path)}", "info")
        logs = parse_input(file_path)
        if not logs:
            continue

        base_name = os.path.splitext(os.path.basename(file_path))[0]

        # CSV parseado
        all_keys = set()
        for rec in logs:
            all_keys.update(rec.keys())
        header = sorted(all_keys - {'source_file'}) + ['IP_Type', 'Country']

        parsed_csv = os.path.join(output_folder, f'{base_name}_parsed.csv')
        with open(parsed_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header, extrasaction='ignore')
            writer.writeheader()
            for rec in logs:
                det = rec.get('detected_ip')
                rec['IP_Type'] = 'Internal' if (det and is_internal_ip(det)) else ('External' if det else 'N/A')
                rec['Country'] = get_country_from_ip(det) if det else 'N/A'
                writer.writerow(rec)

        ips = [r.get('detected_ip') for r in logs if r.get('detected_ip')]
        overall_ips.extend(ips)
        external = sorted({ip for ip in ips if ip and not is_internal_ip(ip)})

        if external:
            print_status(f"  {len(external)} IPs externas únicas", "info")
            if input("  Analizar con APIs? (s/n): ").strip().lower() == 's':
                selected_apis = select_apis()
                results = asyncio.run(run_analysis(external, selected_apis))
                results = enrich_country(results)

                xlsx = generate_xlsx(results, base_name, output_folder)
                html = generate_html(results, base_name, output_folder)
                print_status(f"XLSX: {os.path.basename(xlsx)}", "info")
                print_status(f"HTML: {os.path.basename(html)}", "info")

    # Resumen global
    if overall_ips:
        _write_global_summary(overall_ips, output_folder)

    input(f"\n  {Fore.CYAN}Enter para continuar...{Style.RESET_ALL}")


# ═══════════════════════════════════════════════════════════════
#  Opción 3: Logs Fortinet
# ═══════════════════════════════════════════════════════════════

def fortinet_logs_analysis():
    print(f"\n  {Fore.CYAN}── Análisis de Logs Fortinet ──{Style.RESET_ALL}")

    path = ask_path("Ruta del archivo o carpeta: ")
    if not path:
        return

    file_list = _collect_files(path)
    if not file_list:
        print_status("Sin archivos válidos.", "warning")
        return

    output_folder = get_output_folder()

    for file_path in file_list:
        print_status(f"Procesando: {os.path.basename(file_path)}", "info")
        logs = parse_input(file_path)
        if not logs:
            continue

        base_name = os.path.splitext(os.path.basename(file_path))[0]
        all_keys = set()
        for rec in logs:
            all_keys.update(rec.keys())
        header = sorted(all_keys - {'source_file'}) + ['IP_Type', 'Connection_Status']

        csv_path = os.path.join(output_folder, f'{base_name}_fortinet.csv')
        counts = Counter()

        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header, extrasaction='ignore')
            writer.writeheader()
            for rec in logs:
                det = rec.get('detected_ip')
                rec['IP_Type'] = 'Internal' if (det and is_internal_ip(det)) else ('External' if det else 'N/A')
                status = analyze_fortinet_log(rec)
                rec['Connection_Status'] = status
                counts[status] += 1
                writer.writerow(rec)

        print(f"    {Fore.GREEN}Success:{counts['Success']}{Style.RESET_ALL} "
              f"{Fore.RED}Failure:{counts['Failure']}{Style.RESET_ALL} "
              f"{Fore.YELLOW}Unknown:{counts['Unknown']}{Style.RESET_ALL}")
        print_status(f"CSV: {os.path.basename(csv_path)}", "info")

    input(f"\n  {Fore.CYAN}Enter para continuar...{Style.RESET_ALL}")


# ═══════════════════════════════════════════════════════════════
#  Utilidades internas
# ═══════════════════════════════════════════════════════════════

def _collect_files(path):
    """Recolecta archivos válidos de un path."""
    valid = {'.csv', '.txt', '.log', '.json', '.jsonl', '.cef'}
    if os.path.isdir(path):
        files = []
        for root, _, filenames in os.walk(path):
            for f in filenames:
                if os.path.splitext(f)[1].lower() in valid:
                    files.append(os.path.join(root, f))
        return files
    return [path]


def _print_quick_summary(results):
    """Resumen compacto en consola."""
    risk_counts = Counter(r.get("risk_level", "N/A") for r in results)
    parts = []
    colors = {"CRITICAL": Fore.RED, "HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.GREEN, "SAFE": Fore.CYAN}
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
        n = risk_counts.get(level, 0)
        if n > 0:
            parts.append(f"{colors.get(level, '')}{level}:{n}{Style.RESET_ALL}")
    if parts:
        print(f"\n  Resultado: {' | '.join(parts)}")


def _write_global_summary(all_ips, output_folder):
    """Escribe resumen global de logs."""
    unique = {ip for ip in all_ips if ip}
    external = {ip for ip in unique if not is_internal_ip(ip)}
    top10 = Counter(all_ips).most_common(10)

    path = os.path.join(output_folder, "global_summary.txt")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"Total IPs: {len(all_ips)}\n")
        f.write(f"Únicas: {len(unique)}\n")
        f.write(f"Externas: {len(external)}\n\n")
        f.write("Top 10:\n")
        for ip, count in top10:
            f.write(f"  {ip}: {count}\n")

    print(f"\n  Total: {len(all_ips)} | Únicas: {len(unique)} | Externas: {len(external)}")
    print_status(f"Resumen: {os.path.basename(path)}", "info")


# ═══════════════════════════════════════════════════════════════
#  Menú
# ═══════════════════════════════════════════════════════════════

def menu():
    while True:
        print(f"\n  {Fore.CYAN}═══ LogIPCore ═══{Style.RESET_ALL}")
        print(f"  [1] Analizar IPs")
        print(f"  [2] Analizar logs")
        print(f"  [3] Analizar logs Fortinet")
        print(f"  [4] Salir")

        opt = input(f"  > ").strip()
        if opt == "1":
            simple_ip_analysis()
        elif opt == "2":
            logs_analysis()
        elif opt == "3":
            fortinet_logs_analysis()
        elif opt == "4":
            print(f"  {Fore.CYAN}Hasta pronto.{Style.RESET_ALL}\n")
            break


def main():
    colorama_init(autoreset=True)
    show_banner()
    load_config()

    # Status de APIs
    apis = [
        ("AbuseIPDB", "IP_ABUSE_API_KEY"),
        ("VirusTotal", "VIRUSTOTAL_API_KEY"),
        ("CriminalIP", "CRIMINAL_IP_API_KEY"),
    ]
    status = " | ".join(
        f"{Fore.GREEN}{name} ✓{Style.RESET_ALL}" if os.environ.get(key)
        else f"{Fore.RED}{name} ✗{Style.RESET_ALL}"
        for name, key in apis
    )
    print(f"  APIs: {status}\n")

    menu()


# ═══════════════════════════════════════════════════════════════
#  Modo CLI (no interactivo)
# ═══════════════════════════════════════════════════════════════

def _parse_api_arg(apis_str):
    """Convierte argumento de APIs CLI a lista."""
    if apis_str == "all":
        return ["ipabuse", "virustotal", "criminalip", "tor"]
    return [a.strip() for a in apis_str.split(",") if a.strip()]


def run_cli(args):
    """Ejecuta análisis en modo no interactivo."""
    colorama_init(autoreset=True)
    load_config()

    from src.utils import clean_path
    file_path = clean_path(args.file)

    if not os.path.exists(file_path):
        print_status(f"Ruta no encontrada: {file_path}", "error")
        return

    output_folder = get_output_folder()
    selected_apis = _parse_api_arg(args.apis)

    if args.mode == "ips":
        logs = parse_input(file_path)
        ips = [l.get('detected_ip') for l in logs if l.get('detected_ip')]
        unique_external = sorted({ip for ip in ips if ip and not is_internal_ip(ip)})

        if not unique_external:
            print_status("No hay IPs externas.", "warning")
            return

        print_status(f"{len(unique_external)} IPs externas únicas", "info")
        results = asyncio.run(run_analysis(unique_external, selected_apis))
        results = enrich_country(results)

        xlsx = generate_xlsx(results, args.case, output_folder)
        html = generate_html(results, args.case, output_folder)
        print_status(f"XLSX: {xlsx}", "info")
        print_status(f"HTML: {html}", "info")
        _print_quick_summary(results)

    elif args.mode == "logs":
        file_list = _collect_files(file_path)
        overall_ips = []

        for fp in file_list:
            print_status(f"Procesando: {os.path.basename(fp)}", "info")
            logs = parse_input(fp)
            if not logs:
                continue

            base_name = os.path.splitext(os.path.basename(fp))[0]
            all_keys = set()
            for rec in logs:
                all_keys.update(rec.keys())
            header = sorted(all_keys - {'source_file'}) + ['IP_Type', 'Country']

            parsed_csv = os.path.join(output_folder, f'{base_name}_parsed.csv')
            with open(parsed_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=header, extrasaction='ignore')
                writer.writeheader()
                for rec in logs:
                    det = rec.get('detected_ip')
                    rec['IP_Type'] = 'Internal' if (det and is_internal_ip(det)) else ('External' if det else 'N/A')
                    rec['Country'] = get_country_from_ip(det) if det else 'N/A'
                    writer.writerow(rec)

            ips = [r.get('detected_ip') for r in logs if r.get('detected_ip')]
            overall_ips.extend(ips)
            external = sorted({ip for ip in ips if ip and not is_internal_ip(ip)})

            if external:
                results = asyncio.run(run_analysis(external, selected_apis))
                results = enrich_country(results)
                generate_xlsx(results, base_name, output_folder)
                generate_html(results, base_name, output_folder)

        if overall_ips:
            _write_global_summary(overall_ips, output_folder)

    elif args.mode == "fortinet":
        file_list = _collect_files(file_path)
        for fp in file_list:
            print_status(f"Procesando: {os.path.basename(fp)}", "info")
            logs = parse_input(fp)
            if not logs:
                continue

            base_name = os.path.splitext(os.path.basename(fp))[0]
            all_keys = set()
            for rec in logs:
                all_keys.update(rec.keys())
            header = sorted(all_keys - {'source_file'}) + ['IP_Type', 'Connection_Status']

            csv_path = os.path.join(output_folder, f'{base_name}_fortinet.csv')
            counts = Counter()
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=header, extrasaction='ignore')
                writer.writeheader()
                for rec in logs:
                    det = rec.get('detected_ip')
                    rec['IP_Type'] = 'Internal' if (det and is_internal_ip(det)) else ('External' if det else 'N/A')
                    status = analyze_fortinet_log(rec)
                    rec['Connection_Status'] = status
                    counts[status] += 1
                    writer.writerow(rec)

            print(f"  Success:{counts['Success']} Failure:{counts['Failure']} Unknown:{counts['Unknown']}")


if __name__ == "__main__":
    main()
