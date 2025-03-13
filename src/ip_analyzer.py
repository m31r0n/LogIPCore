# src/ip_analyzer.py
import asyncio
import aiohttp
import json
import os

class IPAnalyzer:
    """
    Clase que encapsula el análisis de IPs utilizando diferentes APIs.
    Cada método asíncrono se encarga de una consulta con manejo de reintentos.
    Se utilizan semáforos para limitar las solicitudes concurrentes a cada API.
    """
    def __init__(self, session, selected_apis, tor_nodes):
        self.session = session
        self.selected_apis = selected_apis
        self.tor_nodes = tor_nodes
        self.semaphores = {
            "criminalip": asyncio.Semaphore(1),
            "ipabuse": asyncio.Semaphore(2),
            "virustotal": asyncio.Semaphore(2)
        }

    async def check_ip_abuse(self, ip):
        if "ipabuse" not in self.selected_apis:
            return "N/A"
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': os.getenv('IP_ABUSE_API_KEY'), 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        retries = 3
        delay = 2
        for _ in range(retries):
            try:
                async with self.semaphores["ipabuse"]:
                    async with self.session.get(url, headers=headers, params=params, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            return data.get('data', {}).get('abuseConfidenceScore', 0)
            except Exception:
                pass
            await asyncio.sleep(delay)
        return 'Error'

    async def check_virus_total(self, ip):
        if "virustotal" not in self.selected_apis:
            return "N/A"
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {'x-apikey': os.getenv('VIRUSTOTAL_API_KEY')}
        retries = 3
        delay = 2
        for _ in range(retries):
            try:
                async with self.semaphores["virustotal"]:
                    async with self.session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            return data.get('data', {}).get('attributes', {})\
                                       .get('last_analysis_stats', {}).get('malicious', 0)
            except Exception:
                pass
            await asyncio.sleep(delay)
        return 'Error'

    async def check_criminal_ip(self, ip):
        if "criminalip" not in self.selected_apis:
            return {"result": "N/A", "country": "N/A"}
        url = f'https://api.criminalip.io/v1/asset/ip/summary?ip={ip}'
        headers = {'x-api-key': os.getenv('CRIMINAL_IP_API_KEY'), 'Accept': 'application/json'}
        retries = 3
        delay = 2
        for _ in range(retries):
            try:
                async with self.semaphores["criminalip"]:
                    async with self.session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            print("=== Respuesta Criminal IP ===")
                            print(json.dumps(data, indent=2))
                            scores = data.get("score", {})
                            inbound_score = scores.get("inbound", None)
                            outbound_score = scores.get("outbound", None)
                            score_priority = ["Critical", "Dangerous", "Moderate", "Low", "Safe"]
                            if inbound_score in score_priority and outbound_score in score_priority:
                                result = inbound_score if score_priority.index(inbound_score) < score_priority.index(outbound_score) else outbound_score
                            elif inbound_score in score_priority:
                                result = inbound_score
                            elif outbound_score in score_priority:
                                result = outbound_score
                            else:
                                result = 'N/A'
                            country = data.get("country", "N/A")
                            return {"result": result, "country": country}
            except Exception:
                pass
            await asyncio.sleep(delay)
        return {"result": "Error", "country": "N/A"}

    async def check_tor(self, ip):
        if "tor" not in self.selected_apis:
            return "N/A"
        return ip in self.tor_nodes

    def calculate_malicious_score(self, analysis):
        score = 0
        if "ipabuse" in self.selected_apis and isinstance(analysis.get('IPAbuse'), int):
            score += analysis.get('IPAbuse')
        if "virustotal" in self.selected_apis and isinstance(analysis.get('VirusTotal'), int):
            score += analysis.get('VirusTotal') * 10
        if "criminalip" in self.selected_apis and isinstance(analysis.get('CriminalIP'), str):
            score_map = {"Safe": 0, "Low": 10, "Moderate": 50, "Dangerous": 75, "Critical": 100}
            score += score_map.get(analysis.get('CriminalIP'), 0)
        if "tor" in self.selected_apis and analysis.get('TOR') is True and score > 0:
            score += 50
        return score

    async def analyze_ip(self, ip):
        tasks = [
            self.check_ip_abuse(ip),
            self.check_virus_total(ip),
            self.check_criminal_ip(ip),
            self.check_tor(ip)
        ]
        results = await asyncio.gather(*tasks)
        analysis = {
            'IPAbuse': results[0],
            'VirusTotal': results[1],
            'CriminalIP': results[2].get("result") if isinstance(results[2], dict) else results[2],
            'TOR': results[3],
            'country': results[2].get("country") if isinstance(results[2], dict) else "N/A"
        }
        analysis['MaliciousScore'] = self.calculate_malicious_score(analysis)
        return analysis
