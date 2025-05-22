import socket
import re
import requests
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

# Detección de servicios (similar a Nmap)
SERVICE_SIGNATURES = {
    21: {"name": "FTP", "probe": b"USER anonymous\r\n", "match": r"220.*FTP"},
    22: {"name": "SSH", "probe": b"\r\n", "match": r"SSH-\d\.\d-OpenSSH"},
    23: {"name": "Telnet", "probe": b"\r\n", "match": r"Telnet"},
    25: {"name": "SMTP", "probe": b"EHLO test\r\n", "match": r"SMTP"},
    80: {"name": "HTTP", "probe": b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "match": r"HTTP/1\."},
    # Puedes añadir más firmas aquí
}

class VulnerabilityScanner:
    """Escáner de vulnerabilidades basado en detección de servicios"""

    def __init__(self):
        pass

    def scan_port(self, ip: str, port: int) -> Dict:
        """Escanea un puerto y devuelve información del servicio si se detecta"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = self._grab_banner(sock, port)
                    service = SERVICE_SIGNATURES.get(port, {}).get("name", "Unknown")
                    return {"ip": ip, "port": port, "banner": banner, "service": service}
        except Exception as e:
            logger.error(f"Error scanning {ip}:{port} → {e}")
        return {}

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Mejor detección de banners con coincidencia de patrones"""
        try:
            if port in SERVICE_SIGNATURES:
                sock.send(SERVICE_SIGNATURES[port]["probe"])
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if re.search(SERVICE_SIGNATURES[port]["match"], banner, re.IGNORECASE):
                    return banner.strip()
        except Exception:
            pass
        return ""

class CVEScanner:
    """Consulta de CVEs desde el NVD (requiere internet)"""
    
    @staticmethod
    def check_cves(service: str, version: str) -> List[Dict]:
        """Consulta vulnerabilidades conocidas (CVEs) para un servicio"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service}+{version}"
            response = requests.get(url, timeout=10)
            return response.json().get("result", {}).get("CVE_Items", [])
        except Exception as e:
            logger.error(f"CVE check failed: {str(e)}")
            return []

