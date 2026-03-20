# LogIPCore

Herramienta CLI para análisis de reputación de IPs y parsing de logs de seguridad orientada a **DFIR**.
Consulta AbuseIPDB, VirusTotal y CriminalIP, y genera reportes XLSX y HTML con gráficas.

## Instalación

```bash
git clone https://github.com/m31r0n/LogIPCore
cd LogIPCore
pip install -r requirements.txt
```

Configura tus API keys:
```bash
cp .env.example .env
# Edita .env con tus keys
```

Descarga [GeoLite2-Country.mmdb](https://dev.maxmind.com/geoip/geoip2/geolite2/) en `data/`.

## Uso

```bash
python run.py
```

### Opciones

| # | Función | Output |
|---|---------|--------|
| 1 | Analizar archivo de IPs | XLSX (4 pestañas) + HTML con gráficas |
| 2 | Analizar logs genéricos | CSV parseado + XLSX/HTML (opcional) |
| 3 | Analizar logs Fortinet | CSV con Connection_Status |

### Output XLSX (4 pestañas)

- **Resumen**: IP, Riesgo, Score, AbuseIPDB, VirusTotal, CriminalIP, TOR, País
- **Infraestructura**: VPN, TOR, Proxy, Hosting, Cloud, Scanner, Darkweb
- **Red**: Puertos abiertos, CVEs, dominios, honeypot, IDS
- **WHOIS**: País, ciudad, ASN, organización

### Reporte HTML

Informe visual con gráficas (Chart.js) diseñado para copiar/pegar en informes DFIR:
- Distribución de riesgo (doughnut) y países (barras)
- Hallazgos principales (VPN, TOR, scanners, darkweb, vulnerabilidades)
- Tablas detalladas por sección

## Estructura

```
LogIPCore/
├── run.py              # Punto de entrada
├── .env                # API keys (gitignored)
├── data/               # GeoLite2-Country.mmdb
├── output/             # Reportes generados (gitignored)
├── config/             # config.ini, fortinet_patterns.json
├── src/
│   ├── main.py         # Menú y flujo principal
│   ├── ip_analyzer.py  # Consultas async a APIs
│   ├── report.py       # Generador XLSX + HTML
│   ├── log_parser.py   # Parsing de logs
│   ├── fortinet_analyzer.py
│   ├── config.py       # Carga .env + config.ini
│   ├── utils.py        # Helpers
│   └── banner.py
└── tests/
```

## Licencia

MIT
