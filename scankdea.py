#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
⚡ ScanKDea ⚡
============================================
Scanner de Seguridad Avanzado en Python
Desarrollado para análisis de redes éticos
============================================
ADVERTENCIA: Este script debe utilizarse SOLAMENTE en entornos controlados y con autorización.
El uso no autorizado de herramientas de escaneo puede ser ilegal y no ético.
"""

import argparse
import socket
import threading
import time
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Dict, Set, Optional
import logging
import random
import os
from dataclasses import dataclass
import json

# Intentar importar colorama para colores en la terminal
try:
    import colorama
    from colorama import Fore, Style
    colorama.init()
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ScanKDea")

# Definición de servicios comunes por puerto
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

@dataclass
class ScanResult:
    """Almacena resultados de escaneo de un puerto específico"""
    host: str
    port: int
    status: str
    service: str = ""
    banner: str = ""
    response_time: float = 0.0


class AdvancedPortScanner:
    """Escáner de puertos avanzado con múltiples técnicas de escaneo"""
    
    def __init__(self, timeout: float = 1.0, threads: int = 100, verbose: bool = False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.results: List[ScanResult] = []
        self.stop_scan = False
        self.start_time = 0
        self.scan_statistics = {
            "total_hosts": 0,
            "total_ports": 0,
            "open_ports": 0,
            "closed_ports": 0,
            "filtered_ports": 0,
            "scan_time": 0,
            "scan_rate": 0
        }
        self.os_detection_signatures = {
            "Linux": [
                {"port": 22, "pattern": "SSH-2.0-OpenSSH"},
                {"port": 80, "pattern": "Server: Apache"},
            ],
            "Windows": [
                {"port": 445, "pattern": "Windows"},
                {"port": 3389, "pattern": "Microsoft"},
                {"port": 80, "pattern": "IIS"},
            ],
            "macOS": [
                {"port": 548, "pattern": "Apple"},
                {"port": 5900, "pattern": "VNC"},
            ],
            "Cisco": [
                {"port": 23, "pattern": "Cisco"},
                {"port": 22, "pattern": "SSH-2.0-Cisco"},
            ]
        }
        
        # Carga las firmas de servicios desde un archivo si existe
        self.service_signatures = COMMON_PORTS
        self._load_service_signatures()
    
    def _load_service_signatures(self):
        """Carga las firmas de servicios desde un archivo"""
        try:
            signatures_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "service_signatures.txt")
            if os.path.exists(signatures_path):
                with open(signatures_path, "r") as f:
                    for line in f:
                        if line.strip() and not line.startswith("#"):
                            parts = line.strip().split(":")
                            if len(parts) == 2:
                                try:
                                    port = int(parts[0])
                                    service = parts[1]
                                    self.service_signatures[port] = service
                                except ValueError:
                                    pass
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error cargando firmas de servicios: {str(e)}")
    
    def scan_range(self, target: str, port_range: str, scan_type: str = "tcp_connect") -> List[ScanResult]:
        """Escanea un rango de puertos en el objetivo especificado"""
        self.start_time = time.time()
        
        try:
            # Validar dirección IP
            if '/' in target:  # Notación CIDR
                try:
                    hosts = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
                except ValueError as e:
                    logger.error(f"Rango CIDR inválido: {str(e)}")
                    return []
            else:
                try:
                    # Primero intentar como IP
                    socket.inet_aton(target)
                    hosts = [target]
                except socket.error:
                    try:
                        # Intentar resolver nombre de dominio
                        ip = socket.gethostbyname(target)
                        hosts = [ip]
                        logger.info(f"Nombre de dominio resuelto: {target} -> {ip}")
                    except socket.gaierror:
                        logger.error(f"No se pudo resolver el nombre de host: {target}")
                        return []
        except Exception as e:
            logger.error(f"Error procesando el objetivo: {str(e)}")
            return []
        
        # Parsear rango de puertos
        try:
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                ports = range(start_port, end_port + 1)
            elif ',' in port_range:
                ports = list({int(p) for p in port_range.split(',')})  # Usar set para eliminar duplicados
            else:
                ports = [int(port_range)]
                
            # Validar puertos
            ports = [p for p in ports if 0 < p <= 65535]
            if not ports:
                logger.error("No hay puertos válidos para escanear")
                return []
                
        except ValueError:
            logger.error("Formato de puertos inválido. Use '80', '1-1000' o '22,80,443'")
            return []
        
        # Configurar método de escaneo basado en el tipo
        scan_methods = {
            "tcp_connect": self._tcp_connect_scan,
            "syn": self._syn_scan,
            "udp": self._udp_scan,
            "stealth": self._stealth_scan,
            "full": self._full_scan
        }
        
        scan_method = scan_methods.get(scan_type, self._tcp_connect_scan)
        
        # Actualizar estadísticas
        self.scan_statistics["total_hosts"] = len(hosts)
        self.scan_statistics["total_ports"] = len(ports)
        
        if COLOR_SUPPORT:
            logger.info(f"{Fore.GREEN}Iniciando escaneo de {Fore.CYAN}{len(hosts)}{Fore.GREEN} host(s) y {Fore.CYAN}{len(ports)}{Fore.GREEN} puerto(s){Style.RESET_ALL}")
            logger.info(f"{Fore.GREEN}Método de escaneo: {Fore.CYAN}{scan_type}{Style.RESET_ALL}")
        else:
            logger.info(f"Iniciando escaneo de {len(hosts)} host(s) y {len(ports)} puerto(s)")
            logger.info(f"Método de escaneo: {scan_type}")
        
        tasks = []
        self.results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for host in hosts:
                for port in ports:
                    if self.stop_scan:
                        break
                    tasks.append(executor.submit(scan_method, host, port))
            
            total_tasks = len(tasks)
            completed = 0
            
            for future in tasks:
                if self.stop_scan:
                    break
                try:
                    result = future.result()
                    if result:
                        if result.status == "open":
                            self.scan_statistics["open_ports"] += 1
                        elif "filtered" in result.status:
                            self.scan_statistics["filtered_ports"] += 1
                        else:
                            self.scan_statistics["closed_ports"] += 1
                        self.results.append(result)
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Error en tarea de escaneo: {str(e)}")
                
                completed += 1
                if self.verbose and completed % 50 == 0:
                    progress = (completed/total_tasks)*100
                    if COLOR_SUPPORT:
                        logger.info(f"{Fore.GREEN}Progreso: {Fore.CYAN}{completed}/{total_tasks} ({progress:.1f}%){Style.RESET_ALL}")
                    else:
                        logger.info(f"Progreso: {completed}/{total_tasks} ({progress:.1f}%)")
        
        # Calcular estadísticas finales
        scan_time = time.time() - self.start_time
        self.scan_statistics["scan_time"] = scan_time
        self.scan_statistics["scan_rate"] = total_tasks / scan_time if scan_time > 0 else 0
        
        if COLOR_SUPPORT:
            logger.info(f"{Fore.GREEN}Escaneo completado en {Fore.CYAN}{scan_time:.2f}{Fore.GREEN} segundos{Style.RESET_ALL}")
            logger.info(f"{Fore.GREEN}Puertos abiertos encontrados: {Fore.CYAN}{self.scan_statistics['open_ports']}{Style.RESET_ALL}")
        else:
            logger.info(f"Escaneo completado en {scan_time:.2f} segundos")
            logger.info(f"Puertos abiertos encontrados: {self.scan_statistics['open_ports']}")
        
        self._detect_os()
        
        return sorted(self.results, key=lambda x: (x.host, x.port))
    
    def _tcp_connect_scan(self, host: str, port: int) -> Optional[ScanResult]:
        """Realiza un escaneo TCP Connect básico"""
        try:
            start_time = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                
                result = sock.connect_ex((host, port))
                response_time = time.time() - start_time
                
                if result == 0:
                    service = self.service_signatures.get(port, "Desconocido")
                    banner = self._grab_banner(sock)
                    
                    if self.verbose:
                        if COLOR_SUPPORT:
                            logger.info(f"{Fore.GREEN}Puerto abierto: {Fore.CYAN}{host}:{port}{Fore.GREEN} - {service}{Style.RESET_ALL}")
                        else:
                            logger.info(f"Puerto abierto: {host}:{port} - {service}")
                    
                    return ScanResult(
                        host=host,
                        port=port,
                        status="open",
                        service=service,
                        banner=banner,
                        response_time=response_time
                    )
                
        except (socket.timeout, socket.error):
            pass
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error escaneando {host}:{port} - {str(e)}")
        
        return None
    
    def _syn_scan(self, host: str, port: int) -> Optional[ScanResult]:
        """Simula un escaneo SYN (se requieren permisos root para un verdadero SYN scan)"""
        return self._tcp_connect_scan(host, port)
    
    def _udp_scan(self, host: str, port: int) -> Optional[ScanResult]:
        """Realiza un escaneo UDP básico"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                
                sock.sendto(b'', (host, port))
                
                try:
                    data, _ = sock.recvfrom(1024)
                    service = self.service_signatures.get(port, "Desconocido")
                    
                    if self.verbose:
                        if COLOR_SUPPORT:
                            logger.info(f"{Fore.GREEN}Puerto UDP abierto: {Fore.CYAN}{host}:{port}{Fore.GREEN} - {service}{Style.RESET_ALL}")
                        else:
                            logger.info(f"Puerto UDP abierto: {host}:{port} - {service}")
                    
                    return ScanResult(
                        host=host,
                        port=port,
                        status="open",
                        service=service,
                        banner=data.decode('utf-8', errors='ignore')
                    )
                except socket.timeout:
                    return ScanResult(
                        host=host,
                        port=port,
                        status="open|filtered",
                        service=self.service_signatures.get(port, "Desconocido")
                    )
                
        except (socket.timeout, socket.error):
            pass
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error escaneando UDP {host}:{port} - {str(e)}")
        
        return None
    
    def _stealth_scan(self, host: str, port: int) -> Optional[ScanResult]:
        """Simula un escaneo sigiloso variando los tiempos de conexión"""
        time.sleep(random.uniform(0.1, 0.5))
        return self._tcp_connect_scan(host, port)
    
    def _full_scan(self, host: str, port: int) -> Optional[ScanResult]:
        """Realiza un escaneo completo combinando técnicas"""
        result = self._tcp_connect_scan(host, port)
        if result:
            return result
        
        if port < 1024:
            return self._udp_scan(host, port)
        
        return None
    
    def _grab_banner(self, sock: socket.socket) -> str:
        """Intenta obtener el banner del servicio"""
        banner = ""
        try:
            sock.settimeout(0.5)
            probes = {
                21: b"USER anonymous\r\n",
                22: b"\r\n",
                25: b"EHLO test\r\n",
                80: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                110: b"USER test\r\n",
                143: b"A001 CAPABILITY\r\n",
                443: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                3306: b"\x0a",
                5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
            }
            
            port = sock.getpeername()[1]
            if port in probes:
                sock.send(probes[port])
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except (socket.timeout, socket.error):
            pass
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error obteniendo banner: {str(e)}")
        
        return banner
    
    def _detect_os(self):
        """Intenta detectar el sistema operativo basado en puertos abiertos y banners"""
        if not self.results:
            return
        
        host_results = {}
        for result in self.results:
            if result.host not in host_results:
                host_results[result.host] = []
            host_results[result.host].append(result)
        
        for host, results in host_results.items():
            os_scores = {"Linux": 0, "Windows": 0, "macOS": 0, "Cisco": 0, "Otro": 0}
            
            open_ports = [r.port for r in results if r.status == "open"]
            
            if 22 in open_ports and 80 in open_ports and 443 in open_ports:
                os_scores["Linux"] += 2
            
            if 135 in open_ports or (139 in open_ports and 445 in open_ports):
                os_scores["Windows"] += 3
            
            if 548 in open_ports or 5900 in open_ports:
                os_scores["macOS"] += 2
            
            if 23 in open_ports and 22 in open_ports and 80 not in open_ports:
                os_scores["Cisco"] += 2
            
            for result in results:
                if result.banner:
                    for os_name, signatures in self.os_detection_signatures.items():
                        for sig in signatures:
                            if sig["port"] == result.port and sig["pattern"].lower() in result.banner.lower():
                                os_scores[os_name] += 3
            
            max_score = max(os_scores.values())
            if max_score > 0:
                probable_os = [os for os, score in os_scores.items() if score == max_score]
                
                if self.verbose and probable_os:
                    if COLOR_SUPPORT:
                        logger.info(f"{Fore.GREEN}Sistema operativo probable para {Fore.CYAN}{host}{Fore.GREEN}: {Fore.YELLOW}{', '.join(probable_os)}{Style.RESET_ALL}")
                    else:
                        logger.info(f"Sistema operativo probable para {host}: {', '.join(probable_os)}")
    
    def get_statistics(self) -> Dict:
        """Devuelve estadísticas del escaneo"""
        return self.scan_statistics

def print_results(results: List[ScanResult]):
    """Imprime los resultados del escaneo en formato tabular"""
    if not results:
        try:
            from colorama import Fore, Style
            print(f"\n{Fore.YELLOW}[!] {Style.BRIGHT}No se encontraron puertos abiertos.{Style.RESET_ALL}")
        except ImportError:
            print("\nNo se encontraron puertos abiertos.")
        return
    
    hosts_results = {}
    for result in results:
        if result.host not in hosts_results:
            hosts_results[result.host] = []
        hosts_results[result.host].append(result)
    
    try:
        from colorama import Fore, Style
        
        for host, host_results in hosts_results.items():
            print(f"\n{Fore.GREEN}[+] {Style.BRIGHT}Host: {Fore.CYAN}{host}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}{'-' * 80}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'PUERTO':<10} {'ESTADO':<15} {'SERVICIO':<15} {'BANNER':<40}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}{'-' * 80}{Style.RESET_ALL}")
            
            for result in sorted(host_results, key=lambda x: x.port):
                banner = result.banner[:37] + "..." if len(result.banner) > 40 else result.banner
                
                if result.status == "open":
                    status_color = f"{Fore.GREEN}{result.status}{Style.RESET_ALL}"
                elif "filtered" in result.status:
                    status_color = f"{Fore.YELLOW}{result.status}{Style.RESET_ALL}"
                else:
                    status_color = f"{Fore.RED}{result.status}{Style.RESET_ALL}"
                
                print(f"{Fore.CYAN}{result.port:<10}{Style.RESET_ALL} "
                      f"{status_color:<15} {result.service:<15} {banner}")
            print("")
            
    except ImportError:
        for host, host_results in hosts_results.items():
            print(f"\n[+] Host: {host}")
            print("-" * 80)
            print(f"{'PUERTO':<10} {'ESTADO':<15} {'SERVICIO':<15} {'BANNER':<40}")
            print("-" * 80)
            
            for result in sorted(host_results, key=lambda x: x.port):
                banner = result.banner[:37] + "..." if len(result.banner) > 40 else result.banner
                print(f"{result.port:<10} {result.status:<15} {result.service:<15} {banner}")
            print("")

def print_banner():
    """Imprime un banner atractivo para la herramienta"""
    banner = """
   
                                                                                                                                                                             
                                                      ,--.                                                              
  .--.--.                                         ,--/  /|    ,---,                                                   
 /  /    '.                                    ,---,': / '  .'  .' `\                                             
|  :  /`. /                              ,---, :   : '/ / ,---.'     \                                                
;  |  |--`                           ,-+-. /  ||   '   ,  |   |  .`\  |                         
|  :  ;_       ,---.     ,--.--.    ,--.'|'   |'   |  /   :   : |  '  |   ,---.     ,--.--.    
 \  \    `.   /     \   /       \  |   |  ,"' ||   ;  ;   |   ' '  ;  :  /     \   /       \     
  `----.   \ /    / '  .--.  .-. | |   | /  | |:   '   \  '   | ;  .  | /    /  | .--.  .-. | 
  __ \  \  |.    ' /    \__\/: . . |   | |  | ||   |    ' |   | :  |  '.    ' / |  \__\/: . .   
 /  /`--'  /'   ; :__   ," .--.; | |   | |  |/ '   : |.  \'   : | /  ; '   ;   /|  ," .--.; | 
'--'.     / '   | '.'| /  /  ,.  | |   | |--'  |   | '_\.'|   | '` ,/  '   |  / | /  /  ,.  |   
  `--'---'  |   :    :;  :   .'   \|   |/      '   : |    ;   :  .'    |   :    |;  :   .'   \  
             \   \  / |  ,     .-./'---'       ;   |,'    |   ,.'       \   \  / |  ,     .-./`   
              `----'   `--`---'                '---'      '---'          `----'   `--`---'      `                
                                                                                                                                                                             

                          [ ScanKDea - Advanced Recon Tool ]
    """

    skull = """
                      .--.
                     |o_o |
                     |:_/ |
                    //   \\ \\
                   (|     | )
                  /'\\_   _/`\\\\
                  \\___)=(___/
    """

    version = "v1.0.0"
    author = "Ernesto Lopez"
    team = "Comunidad HackingTeam"

    if COLOR_SUPPORT:
        banner = Fore.CYAN + banner + Style.RESET_ALL
        skull = Fore.RED + skull + Style.RESET_ALL
        version_line = f"{Fore.GREEN}[+] {Style.BRIGHT}Versión: {version}{Style.RESET_ALL}"
        author_line = f"{Fore.GREEN}[+] {Style.BRIGHT}Autor: {author}{Style.RESET_ALL}"
        team_line = f"{Fore.GREEN}[+] {Style.BRIGHT}Equipo: {team}{Style.RESET_ALL}"
        tagline = f"{Fore.YELLOW}[!] {Style.BRIGHT}La herramienta de reconocimiento que deja huella{Style.RESET_ALL}"
    else:
        version_line = f"[+] Versión: {version}"
        author_line = f"[+] Autor: {author}"
        team_line = f"[+] Equipo: {team}"
        tagline = f"[!] La herramienta de reconocimiento que deja huella"

    print(banner)
    print(skull)
    print(version_line)
    print(author_line)
    print(team_line)
    print(tagline)
    print("\n" + "=" * 80 + "\n")


def print_help_menu():
    """Imprime un menú de ayuda atractivo"""
    try:
        from colorama import Fore, Style
        title = f"\n{Fore.CYAN}{Style.BRIGHT}OPCIONES DISPONIBLES DE SCANKDEA{Style.RESET_ALL}\n"
        separator = f"{Fore.BLUE}{'-' * 60}{Style.RESET_ALL}"
    except ImportError:
        title = "\nOPCIONES DISPONIBLES DE SCANKDEA\n"
        separator = '-' * 60
    
    print(title)
    print(separator)
    
    help_options = [
        ("target", "Objetivo a escanear (IP, hostname o rango CIDR)", "Requerido"),
        ("-p, --ports", "Puertos a escanear (ej: 80,443 o 1-1000)", "1-1000"),
        ("-t, --threads", "Número de hilos a utilizar", "100"),
        ("-to, --timeout", "Timeout en segundos para conexiones", "1.0"),
        ("-v, --verbose", "Modo verboso para más detalles", "False"),
        ("-m, --method", "Método de escaneo [tcp_connect, syn, udp, stealth]", "tcp_connect"),
        ("--help", "Muestra este mensaje de ayuda", "")
    ]
    
    try:
        from colorama import Fore, Style
        for option, description, default in help_options:
            if default:
                print(f"{Fore.GREEN}{option:20}{Style.RESET_ALL} {description:45} {Fore.YELLOW}[Default: {default}]{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}{option:20}{Style.RESET_ALL} {description:45}")
    except ImportError:
        for option, description, default in help_options:
            if default:
                print(f"{option:20} {description:45} [Default: {default}]")
            else:
                print(f"{option:20} {description:45}")
    
    print(separator)
    print("\nEJEMPLOS DE USO:")
    print("  python scankdea.py 192.168.1.1")
    print("  python scankdea.py example.com -p 80,443,8080 -v")
    print("  python scankdea.py 192.168.1.0/24 -p 22-1000 -t 200 -m stealth")

def main():
    parser = argparse.ArgumentParser(description="ScanKDea - Escáner de Puertos Avanzado en Python", add_help=False)
    parser.add_argument("target", nargs="?", help="Objetivo a escanear (IP, hostname o rango CIDR)")
    parser.add_argument("-p", "--ports", default="1-1000", help="Puertos a escanear (ej: 80,443 o 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Número de hilos a utilizar")
    parser.add_argument("-to", "--timeout", type=float, default=1.0, help="Timeout en segundos")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verboso")
    parser.add_argument("-m", "--method", choices=["tcp_connect", "syn", "udp", "stealth", "full"], 
                       default="tcp_connect", help="Método de escaneo")
    parser.add_argument("--help", action="store_true", help="Muestra el mensaje de ayuda")
    
    print_banner()
    
    args, unknown = parser.parse_known_args()
    
    if args.help or not args.target:
        print_help_menu()
        return
    
    try:
        scanner = AdvancedPortScanner(
            timeout=args.timeout,
            threads=args.threads,
            verbose=args.verbose
        )
        
        def signal_handler(sig, frame):
            print("\nDetección de Ctrl+C. Deteniendo escaneo...")
            scanner.stop_scan = True
        
        import signal
        signal.signal(signal.SIGINT, signal_handler)
        
        results = scanner.scan_range(args.target, args.ports, args.method)
        
        print_results(results)
        
        if results:
            stats = scanner.get_statistics()
            if COLOR_SUPPORT:
                from colorama import Fore, Style
                print(f"\n{Fore.GREEN}[*] {Style.BRIGHT}Estadísticas del escaneo:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Tiempo total:{Style.RESET_ALL} {stats['scan_time']:.2f} segundos")
                print(f"{Fore.CYAN}Puertos abiertos:{Style.RESET_ALL} {stats['open_ports']}")
                print(f"{Fore.CYAN}Tasa de escaneo:{Style.RESET_ALL} {stats['scan_rate']:.1f} puertos/segundo")
            else:
                print("\n[*] Estadísticas del escaneo:")
                print(f"Tiempo total: {stats['scan_time']:.2f} segundos")
                print(f"Puertos abiertos: {stats['open_ports']}")
                print(f"Tasa de escaneo: {stats['scan_rate']:.1f} puertos/segundo")
                
    except Exception as e:
        logger.error(f"Error durante el escaneo: {str(e)}")
        if args.verbose:
            logger.exception("Detalles del error:")

if __name__ == "__main__":
    main()
