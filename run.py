#!/usr/bin/env python3
"""
LogIPCore - IP & Log Analyzer for DFIR

Uso interactivo:
    python run.py

Uso CLI (no interactivo):
    python run.py -f ips.txt -c caso123
    python run.py -f /logs/ -m logs -c caso456
    python run.py -f fortinet.log -m fortinet -c caso789
    python run.py -f ips.txt -a ipabuse,criminalip -c test
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description="LogIPCore - Analizador de IPs y Logs para DFIR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Sin argumentos = modo interactivo con menú.",
    )
    parser.add_argument("-f", "--file", help="Ruta al archivo o carpeta de IPs/logs")
    parser.add_argument("-c", "--case", default="analysis", help="Nombre del caso (default: analysis)")
    parser.add_argument("-m", "--mode", choices=["ips", "logs", "fortinet"], default="ips",
                        help="Modo: ips (default), logs, fortinet")
    parser.add_argument("-a", "--apis", default="all",
                        help="APIs: all (default), o separadas por coma (ipabuse,virustotal,criminalip,tor)")

    args = parser.parse_args()

    if args.file:
        from src.main import run_cli
        run_cli(args)
    else:
        from src.main import main as interactive
        interactive()


if __name__ == "__main__":
    main()
