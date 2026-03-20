# src/ip_analyzer.py
import asyncio
import aiohttp
import json
import os
import logging

logger = logging.getLogger(__name__)


class IPAnalyzer:
    """
    Analiza IPs usando múltiples APIs de threat intelligence.
    - AbuseIPDB: score de abuso (0-100)
    - VirusTotal: cantidad de detecciones maliciosas
    - CriminalIP: reporte completo (VPN, puertos, vulnerabilidades, hosting, etc.)
    - TOR: verificación contra lista de nodos de salida
    """

    CRIMINAL_IP_FIELDS = [
        "inbound_score", "outbound_score",
        "is_vpn", "is_tor", "is_proxy", "is_hosting", "is_cloud",
        "is_scanner", "is_darkweb", "is_mobile", "is_snort", "is_anonymous_vpn",
        "country", "city", "asn", "org",
        "open_ports_count", "top_ports", "vuln_count", "top_cves",
        "domains_count", "honeypot_count", "ids_count",
        "vpn_name", "categories",
    ]

    def __init__(self, session, selected_apis, tor_nodes=None):
        self.session = session
        self.selected_apis = selected_apis
        self.tor_nodes = tor_nodes or set()
        self.semaphores = {
            "criminalip": asyncio.Semaphore(1),
            "ipabuse": asyncio.Semaphore(2),
            "virustotal": asyncio.Semaphore(2),
        }

    # ─── AbuseIPDB ──────────────────────────────────────────────

    async def check_ip_abuse(self, ip):
        if "ipabuse" not in self.selected_apis:
            return "N/A"
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": os.getenv("IP_ABUSE_API_KEY"), "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        for attempt in range(3):
            try:
                async with self.semaphores["ipabuse"]:
                    async with self.session.get(url, headers=headers, params=params, timeout=15) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return data.get("data", {}).get("abuseConfidenceScore", 0)
                        elif resp.status == 429:
                            logger.warning(f"AbuseIPDB rate limit para {ip}, reintentando...")
                            await asyncio.sleep(5)
                            continue
            except Exception as e:
                logger.debug(f"AbuseIPDB error {ip} intento {attempt+1}: {e}")
            await asyncio.sleep(2)
        return "Error"

    # ─── VirusTotal ─────────────────────────────────────────────

    async def check_virus_total(self, ip):
        if "virustotal" not in self.selected_apis:
            return "N/A"
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
        for attempt in range(3):
            try:
                async with self.semaphores["virustotal"]:
                    async with self.session.get(url, headers=headers, timeout=15) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return (data.get("data", {})
                                    .get("attributes", {})
                                    .get("last_analysis_stats", {})
                                    .get("malicious", 0))
                        elif resp.status == 429:
                            logger.warning(f"VirusTotal rate limit para {ip}, reintentando...")
                            await asyncio.sleep(15)
                            continue
            except Exception as e:
                logger.debug(f"VirusTotal error {ip} intento {attempt+1}: {e}")
            await asyncio.sleep(2)
        return "Error"

    # ─── Criminal IP (Reporte Completo) ─────────────────────────

    async def check_criminal_ip(self, ip):
        """
        Usa /v1/asset/ip/report para obtener datos completos:
        - Issues: VPN, TOR, proxy, hosting, cloud, scanner, darkweb
        - Score: inbound/outbound
        - Whois: ASN, organización, país, ciudad
        - Puertos abiertos, vulnerabilidades, dominios
        - Honeypot detections, IDS alerts
        """
        if "criminalip" not in self.selected_apis:
            return self._empty_criminal_ip()

        url = "https://api.criminalip.io/v1/asset/ip/report"
        headers = {"x-api-key": os.getenv("CRIMINAL_IP_API_KEY")}
        params = {"ip": ip}

        for attempt in range(3):
            try:
                async with self.semaphores["criminalip"]:
                    async with self.session.get(url, headers=headers, params=params, timeout=30) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return self._parse_criminal_ip_report(data)
                        elif resp.status == 429:
                            logger.warning(f"CriminalIP rate limit para {ip}, esperando...")
                            await asyncio.sleep(10)
                            continue
                        else:
                            logger.warning(f"CriminalIP status {resp.status} para {ip}")
            except Exception as e:
                logger.debug(f"CriminalIP error {ip} intento {attempt+1}: {e}")
            await asyncio.sleep(3)
        return self._error_criminal_ip()

    def _parse_criminal_ip_report(self, data):
        """Extrae campos clave del reporte completo de Criminal IP."""
        issues = data.get("issues", {})
        score = data.get("score", {})

        # Whois
        whois_list = data.get("whois", {}).get("data", [])
        whois = whois_list[0] if whois_list else {}

        # Puertos
        port_info = data.get("port", {})
        ports = port_info.get("data", [])
        top_ports = ", ".join(
            f"{p.get('open_port_no')}/{p.get('protocol', '?')}"
            for p in ports[:10]
        ) if ports else "None"

        # Vulnerabilidades
        vuln_info = data.get("vulnerability", {})
        vulns = vuln_info.get("data", [])
        top_cves = ", ".join(
            f"{v.get('cve_id')}(CVSS:{v.get('cvssv3_score', '?')})"
            for v in vulns[:5]
        ) if vulns else "None"

        # VPN info
        vpn_list = data.get("vpn", {}).get("data", [])
        vpn_name = vpn_list[0].get("vpn_name", "N/A") if vpn_list else "N/A"

        # Categorías
        categories = data.get("ip_category", {}).get("data", [])
        cat_types = ", ".join(c.get("type", "") for c in categories if c.get("type")) if categories else "None"

        return {
            "inbound_score": score.get("inbound", "N/A"),
            "outbound_score": score.get("outbound", "N/A"),
            "is_vpn": issues.get("is_vpn", False),
            "is_tor": issues.get("is_tor", False),
            "is_proxy": issues.get("is_proxy", False),
            "is_hosting": issues.get("is_hosting", False),
            "is_cloud": issues.get("is_cloud", False),
            "is_scanner": issues.get("is_scanner", False),
            "is_darkweb": issues.get("is_darkweb", False),
            "is_mobile": issues.get("is_mobile", False),
            "is_snort": issues.get("is_snort", False),
            "is_anonymous_vpn": issues.get("is_anonymous_vpn", False),
            "country": whois.get("org_country_code", "N/A"),
            "city": whois.get("city", "N/A"),
            "asn": whois.get("as_no", "N/A"),
            "org": whois.get("org_name", "N/A"),
            "open_ports_count": port_info.get("count", 0),
            "top_ports": top_ports,
            "vuln_count": vuln_info.get("count", 0),
            "top_cves": top_cves,
            "domains_count": data.get("domain", {}).get("count", 0),
            "honeypot_count": data.get("honeypot", {}).get("count", 0),
            "ids_count": data.get("ids", {}).get("count", 0),
            "vpn_name": vpn_name,
            "categories": cat_types,
            "_raw": data,  # Guardar respuesta completa para JSON export
        }

    def _empty_criminal_ip(self):
        result = {k: "N/A" for k in self.CRIMINAL_IP_FIELDS}
        result["_raw"] = None
        return result

    def _error_criminal_ip(self):
        result = {k: "Error" for k in self.CRIMINAL_IP_FIELDS}
        result["_raw"] = None
        return result

    # ─── TOR Check ──────────────────────────────────────────────

    async def check_tor(self, ip):
        if "tor" not in self.selected_apis:
            return "N/A"
        return ip in self.tor_nodes

    # ─── Score y Clasificación ──────────────────────────────────

    def calculate_malicious_score(self, analysis):
        """Calcula un score combinado de todas las fuentes."""
        score = 0

        # AbuseIPDB (0-100)
        ipabuse = analysis.get("ipabuse_score")
        if isinstance(ipabuse, (int, float)):
            score += ipabuse

        # VirusTotal (detecciones * 10)
        vt = analysis.get("vt_malicious")
        if isinstance(vt, (int, float)):
            score += vt * 10

        # Criminal IP score
        cip = analysis.get("criminal_ip", {})
        score_map = {"Safe": 0, "Low": 10, "Moderate": 50, "Dangerous": 75, "Critical": 100}
        inbound = cip.get("inbound_score", "N/A")
        if inbound in score_map:
            score += score_map[inbound]

        # Indicadores de infraestructura maliciosa
        if cip.get("is_vpn") is True:
            score += 15
        if cip.get("is_proxy") is True:
            score += 15
        if cip.get("is_darkweb") is True:
            score += 30
        if cip.get("is_scanner") is True:
            score += 20
        if cip.get("is_anonymous_vpn") is True:
            score += 20

        # TOR (desde API TOR o Criminal IP)
        tor_node = analysis.get("is_tor_node")
        cip_tor = cip.get("is_tor", False)
        if (tor_node is True or cip_tor is True) and score > 0:
            score += 40

        # Honeypot detections
        honeypot = cip.get("honeypot_count", 0)
        if isinstance(honeypot, int) and honeypot > 0:
            score += min(honeypot * 10, 50)

        # IDS alerts
        ids_count = cip.get("ids_count", 0)
        if isinstance(ids_count, int) and ids_count > 0:
            score += min(ids_count * 15, 50)

        return score

    def classify_risk(self, score):
        """Clasifica el nivel de riesgo según el score."""
        if score >= 200:
            return "CRITICAL"
        elif score >= 100:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "SAFE"

    # ─── Análisis Principal ─────────────────────────────────────

    async def analyze_ip(self, ip):
        """Ejecuta todas las consultas en paralelo y retorna resultado enriquecido."""
        tasks = [
            self.check_ip_abuse(ip),
            self.check_virus_total(ip),
            self.check_criminal_ip(ip),
            self.check_tor(ip),
        ]
        results = await asyncio.gather(*tasks)

        cip = results[2] if isinstance(results[2], dict) else {}

        analysis = {
            "ip": ip,
            "ipabuse_score": results[0],
            "vt_malicious": results[1],
            "criminal_ip": cip,
            "is_tor_node": results[3],
        }

        analysis["malicious_score"] = self.calculate_malicious_score(analysis)
        analysis["risk_level"] = self.classify_risk(analysis["malicious_score"])

        return analysis
