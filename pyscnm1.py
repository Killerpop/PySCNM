#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PysCNM 1.0 - Python Security Network Monitor
Escáner de red avanzado con integración a ExploitDB
Características:
    - Escaneo de puertos TCP y UDP
    - Detección de servicios y versiones
    - Búsqueda automática de vulnerabilidades en ExploitDB (en línea)
    - Multithreading para mayor velocidad
    - Exportación de resultados
"""

import socket
import threading
import sys
import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
from urllib.parse import quote
import os
import re

# ===========================
# COLORES PARA LA CONSOLA
# ===========================

# Códigos de color ANSI
class Colors:
    # Colores básicos
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Colores brillantes
    BRIGHT_RED = '\033[91;1m'
    BRIGHT_GREEN = '\033[92;1m'
    BRIGHT_YELLOW = '\033[93;1m'
    BRIGHT_BLUE = '\033[94;1m'
    BRIGHT_MAGENTA = '\033[95;1m'
    BRIGHT_CYAN = '\033[96;1m'
    BRIGHT_WHITE = '\033[97;1m'
    
    # Estilos
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    # Fondos
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'

# ===========================
# BANNER Y PRESENTACIÓN
# ===========================

def show_banner():
    """Muestra el banner de inicio"""
    banner = f"""
    {Colors.BRIGHT_CYAN}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}                                                           {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}   {Colors.BRIGHT_MAGENTA}██████╗ ██╗   ██╗███████╗ ██████╗███╗   ██╗███╗   ███╗{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}   {Colors.BRIGHT_MAGENTA}██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝████╗  ██║████╗ ████║{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}   {Colors.BRIGHT_BLUE}██████╔╝ ╚████╔╝ ███████╗██║     ██╔██╗ ██║██╔████╔██║{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}   {Colors.BRIGHT_BLUE}██╔═══╝   ╚██╔╝  ╚════██║██║     ██║╚██╗██║██║╚██╔╝██║{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}   {Colors.BRIGHT_GREEN}██║        ██║   ███████║╚██████╗██║ ╚████║██║ ╚═╝ ██║{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}   {Colors.BRIGHT_GREEN}╚═╝        ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═══╝╚═╝     ╚═╝{Colors.RESET}  {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}                                                           {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}                    {Colors.BRIGHT_YELLOW}Version 1.0{Colors.RESET}                            {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}                   {Colors.BRIGHT_RED}By G. Zaballa{Colors.RESET}                           {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}           {Colors.BRIGHT_GREEN}Python Network Vulnerability Scanner{Colors.RESET}            {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}║{Colors.RESET}                                                           {Colors.BRIGHT_CYAN}║{Colors.RESET}
    {Colors.BRIGHT_CYAN}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}
    
           {Colors.CYAN}[*]{Colors.RESET} {Colors.WHITE}Escáner de Red Avanzado - Python Edition{Colors.RESET}
           {Colors.CYAN}[*]{Colors.RESET} {Colors.BRIGHT_YELLOW}Detección: Puertos | Servicios | Versiones | CVEs{Colors.RESET}
           {Colors.CYAN}[*]{Colors.RESET} {Colors.BRIGHT_GREEN}Base de datos de vulnerabilidades integrada{Colors.RESET}
           {Colors.CYAN}[*]{Colors.RESET} {Colors.BRIGHT_RED}Uso Educativo y Ético Solamente{Colors.RESET}
    
    """
    print(banner)

# ===========================
# CLASE PRINCIPAL: NETWORK SCANNER
# ===========================

class NetworkScanner:
    """Clase principal para realizar escaneo de redes y puertos"""
    
    def __init__(self, target):
        """
        Inicializa el escáner
        
        Args:
            target (str): IP o dominio objetivo
        """
        self.target = target
        self.open_ports = {}
        self.os_info = "Desconocido"
        self.lock = threading.Lock()
        self.exploitdb_cache = {}  # Cache para evitar búsquedas duplicadas
        self.timeout_socket = 3
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def resolve_target(self):
        """Resuelve el dominio a IP si es necesario"""
        try:
            ip = socket.gethostbyname(self.target)
            if ip != self.target:
                print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} Dominio resuelto: {self.target} -> {ip}")
                self.target = ip
            return True
        except socket.gaierror:
            print(f"{Colors.BRIGHT_RED}[!]{Colors.RESET} No se pudo resolver el dominio: {self.target}")
            return False

    def detect_os(self):
        """Intenta detectar el SO del objetivo analizando TTL y características"""
        print(f"{Colors.YELLOW}[*]{Colors.RESET} Intentando detectar sistema operativo...")
        try:
            # Intentar puerto 80 (HTTP - común en Linux/Unix)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_socket)
            result = sock.connect_ex((self.target, 80))
            sock.close()
            
            if result == 0:
                self.os_info = "Linux/Unix (probable - puerto 80 abierto)"
                print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} SO detectado: {self.os_info}")
                return
        except Exception as e:
            pass
        
        try:
            # Intentar puerto 445 (SMB - común en Windows)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_socket)
            result = sock.connect_ex((self.target, 445))
            sock.close()
            
            if result == 0:
                self.os_info = "Windows (probable - puerto 445 abierto)"
                print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} SO detectado: {self.os_info}")
                return
        except Exception as e:
            pass
        
        try:
            # Intentar puerto 22 (SSH - común en Linux/Unix)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_socket)
            result = sock.connect_ex((self.target, 22))
            sock.close()
            
            if result == 0:
                self.os_info = "Linux/Unix (probable - puerto 22 abierto)"
                print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} SO detectado: {self.os_info}")
                return
        except Exception as e:
            pass
        
        self.os_info = "Desconocido"
        print(f"{Colors.YELLOW}[*]{Colors.RESET} SO: No se pudo determinar")

    def get_service_name(self, port, protocol='tcp'):
        """Obtiene el nombre del servicio estándar para un puerto"""
        try:
            return socket.getservbyport(port, protocol)
        except:
            return "Desconocido"

    def grab_banner(self, host, port, protocol='TCP'):
        """Intenta obtener el banner (información) del servicio en un puerto - MEJORADO"""
        try:
            if protocol == 'TCP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((host, port))
                
                # Intentar recibir banner inicial (algunos servicios lo envían automáticamente)
                try:
                    sock.settimeout(1)
                    initial_banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
                    if initial_banner:
                        sock.close()
                        return initial_banner
                except:
                    pass
                
                # Si no hay banner inicial, intentar diferentes sondas según el puerto
                try:
                    sock.settimeout(2)
                    
                    # HTTP/HTTPS
                    if port in [80, 443, 8080, 8443, 8000]:
                        sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                        banner = sock.recv(2048).decode('utf-8', errors='ignore')
                    
                    # SSH
                    elif port == 22:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    # FTP
                    elif port in [21, 2121]:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    # SMTP
                    elif port in [25, 587]:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    # Telnet
                    elif port == 23:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    # MySQL
                    elif port == 3306:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    # PostgreSQL
                    elif port == 5432:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    # Por defecto, intentar recibir
                    else:
                        sock.send(b"\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    sock.close()
                    return banner.strip() if banner else None
                    
                except:
                    sock.close()
                    return None
            
            return None
            
        except Exception as e:
            return None

    def extract_version_from_banner(self, banner, service_name):
        """Extrae la versión específica del banner - MEJORADO"""
        if not banner:
            return "Versión desconocida"
        
        banner = banner.strip()
        
        # Patrones comunes de versión
        version_patterns = [
            r'(\d+\.\d+\.?\d*\.?\d*)',  # Patrón numérico general
            r'[vV]ersion[:\s]+([0-9.]+)',
            r'([A-Za-z]+/\d+\.\d+\.?\d*)',  # Ej: Apache/2.4.41
            r'([A-Za-z-]+\s+\d+\.\d+\.?\d*)',  # Ej: nginx 1.18.0
        ]
        
        # HTTP Server
        if 'HTTP' in banner.upper() or 'SERVER' in banner.upper():
            # Buscar Server header
            server_match = re.search(r'[Ss]erver:\s*([^\r\n]+)', banner)
            if server_match:
                return server_match.group(1).strip()
            
            # Buscar en primera línea
            first_line = banner.split('\n')[0]
            if 'HTTP' in first_line:
                return first_line.strip()
        
        # SSH
        if 'SSH' in banner.upper():
            ssh_match = re.search(r'SSH-[\d.]+-([^\s\r\n]+)', banner)
            if ssh_match:
                return f"SSH {ssh_match.group(1)}"
            return banner.split('\n')[0].strip()
        
        # FTP
        if 'FTP' in banner.upper() or service_name.lower() == 'ftp':
            ftp_match = re.search(r'220[- ]([^\r\n]+)', banner)
            if ftp_match:
                return ftp_match.group(1).strip()
        
        # SMTP
        if 'SMTP' in banner.upper() or service_name.lower() == 'smtp':
            smtp_match = re.search(r'220[- ]([^\r\n]+)', banner)
            if smtp_match:
                return smtp_match.group(1).strip()
        
        # MySQL
        if 'MYSQL' in banner.upper() or service_name.lower() == 'mysql':
            # MySQL envía versión en el handshake
            mysql_match = re.search(r'(\d+\.\d+\.\d+)', banner)
            if mysql_match:
                return f"MySQL {mysql_match.group(1)}"
        
        # Buscar cualquier patrón de versión
        for pattern in version_patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        
        # Si no se encontró versión específica, devolver primeros caracteres del banner
        return banner[:80].replace('\n', ' ').replace('\r', '').strip()

    def identify_service_version(self, port, protocol='TCP'):
        """Intenta identificar el servicio y versión en un puerto - MEJORADO"""
        service_name = self.get_service_name(port, protocol.lower())
        version = "Desconocida"
        
        # Intentar banner grabbing
        banner = self.grab_banner(self.target, port, protocol)
        
        if banner:
            version = self.extract_version_from_banner(banner, service_name)
        else:
            # Si no hay banner, intentar identificar por puerto conocido
            known_services = {
                20: ("FTP Data", "FTP Data Transfer"),
                21: ("FTP", "File Transfer Protocol"),
                22: ("SSH", "OpenSSH (versión desconocida)"),
                23: ("Telnet", "Telnet service"),
                25: ("SMTP", "Mail server"),
                53: ("DNS", "Domain Name System"),
                80: ("HTTP", "Web server"),
                110: ("POP3", "Mail server"),
                143: ("IMAP", "Mail server"),
                443: ("HTTPS", "Secure web server"),
                445: ("SMB", "Windows file sharing"),
                3306: ("MySQL", "MySQL database"),
                3389: ("RDP", "Remote Desktop"),
                5432: ("PostgreSQL", "PostgreSQL database"),
                8080: ("HTTP-Proxy", "HTTP Alternate"),
                8443: ("HTTPS-Alt", "HTTPS Alternate"),
            }
            
            if port in known_services:
                service_name, version = known_services[port]
        
        return service_name, version

    def search_exploitdb(self, service, version):
        """Busca vulnerabilidades en ExploitDB usando método simplificado y robusto"""
        
        # Crear clave de cache
        cache_key = f"{service}_{version}"
        
        # Verificar cache
        if cache_key in self.exploitdb_cache:
            return self.exploitdb_cache[cache_key]
        
        exploits = []
        
        try:
            # Limpiar la versión para búsqueda
            search_query = f"{service} {version}"
            
            # Eliminar palabras genéricas que no ayudan en la búsqueda
            search_query = search_query.replace("Versión desconocida", "")
            search_query = search_query.replace("Desconocida", "")
            search_query = search_query.replace("(activo)", "")
            search_query = ' '.join(search_query.split())  # Limpiar espacios múltiples
            
            if not search_query.strip() or search_query.strip().lower() in ['desconocido', 'unknown']:
                self.exploitdb_cache[cache_key] = []
                return []
            
            print(f"    {Colors.YELLOW}[*]{Colors.RESET} Buscando vulnerabilidades para: {search_query}")
            
            # Método simplificado: búsqueda directa con menos parámetros
            api_url = "https://www.exploit-db.com/search"
            
            # Parámetros mínimos necesarios
            params = {
                'q': search_query
            }
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Referer': 'https://www.exploit-db.com/',
                'Upgrade-Insecure-Requests': '1'
            }
            
            response = requests.get(api_url, params=params, headers=headers, timeout=15)
            
            if response.status_code == 200:
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Buscar tabla de exploits
                    exploit_table = soup.find('table', {'id': 'exploits-table'})
                    
                    if exploit_table:
                        # Buscar todas las filas de la tabla
                        rows = exploit_table.find('tbody').find_all('tr') if exploit_table.find('tbody') else []
                        
                        for row in rows[:5]:  # Limitar a 5 resultados
                            try:
                                cells = row.find_all('td')
                                
                                if len(cells) >= 5:
                                    # Extraer información
                                    # Típicamente: fecha, título, tipo, plataforma, autor
                                    
                                    # Buscar link del exploit
                                    title_link = row.find('a', href=re.compile(r'/exploits/\d+'))
                                    
                                    if title_link:
                                        title = title_link.get('title', title_link.text.strip())
                                        href = title_link.get('href', '')
                                        exploit_id = href.split('/')[-1] if '/' in href else ''
                                        
                                        # Buscar CVEs en el título o en celdas especiales
                                        cves = self.extract_cves_from_title(title)
                                        
                                        # Buscar también en toda la fila por si hay CVEs en otras celdas
                                        row_text = row.get_text()
                                        row_cves = self.extract_cves_from_title(row_text)
                                        cves.extend(row_cves)
                                        cves = list(set(cves))  # Eliminar duplicados
                                        
                                        link = f"https://www.exploit-db.com/exploits/{exploit_id}"
                                        
                                        if title and exploit_id:
                                            exploits.append({
                                                'title': title.strip(),
                                                'link': link,
                                                'id': exploit_id,
                                                'cves': cves
                                            })
                            except Exception as e:
                                continue
                    
                    # Método alternativo: buscar por clase o patrón diferente
                    if not exploits:
                        # Buscar links de exploits directamente
                        exploit_links = soup.find_all('a', href=re.compile(r'/exploits/\d+'))
                        
                        for link_tag in exploit_links[:5]:
                            try:
                                title = link_tag.get('title', link_tag.text.strip())
                                href = link_tag.get('href', '')
                                exploit_id = href.split('/')[-1] if '/' in href else ''
                                
                                if not title or not exploit_id:
                                    continue
                                
                                # Extraer CVEs
                                cves = self.extract_cves_from_title(title)
                                
                                # Buscar CVEs en el contexto cercano del link
                                parent = link_tag.find_parent('tr')
                                if parent:
                                    parent_text = parent.get_text()
                                    parent_cves = self.extract_cves_from_title(parent_text)
                                    cves.extend(parent_cves)
                                    cves = list(set(cves))
                                
                                link = f"https://www.exploit-db.com/exploits/{exploit_id}"
                                
                                exploits.append({
                                    'title': title.strip(),
                                    'link': link,
                                    'id': exploit_id,
                                    'cves': cves
                                })
                            except:
                                continue
                    
                    if exploits:
                        print(f"    {Colors.BRIGHT_RED}[!]{Colors.RESET} Encontradas {len(exploits)} vulnerabilidades")
                    else:
                        print(f"    {Colors.GREEN}[✓]{Colors.RESET} No se encontraron vulnerabilidades conocidas")
                
                except Exception as e:
                    print(f"    {Colors.YELLOW}[*]{Colors.RESET} Error al parsear respuesta: {str(e)}")
            
            elif response.status_code == 500:
                print(f"    {Colors.YELLOW}[*]{Colors.RESET} Error del servidor ExploitDB (500). Reintentando con método alternativo...")
                
                # Método alternativo: buscar en la página de búsqueda simple
                try:
                    simple_url = f"https://www.exploit-db.com/?q={quote(search_query)}"
                    simple_response = requests.get(simple_url, headers=headers, timeout=15)
                    
                    if simple_response.status_code == 200:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(simple_response.text, 'html.parser')
                        
                        exploit_links = soup.find_all('a', href=re.compile(r'/exploits/\d+'))
                        
                        for link_tag in exploit_links[:5]:
                            try:
                                title = link_tag.get('title', link_tag.text.strip())
                                href = link_tag.get('href', '')
                                exploit_id = href.split('/')[-1] if '/' in href else ''
                                
                                if not title or not exploit_id:
                                    continue
                                
                                cves = self.extract_cves_from_title(title)
                                link = f"https://www.exploit-db.com/exploits/{exploit_id}"
                                
                                exploits.append({
                                    'title': title.strip(),
                                    'link': link,
                                    'id': exploit_id,
                                    'cves': cves
                                })
                            except:
                                continue
                        
                        if exploits:
                            print(f"    {Colors.BRIGHT_RED}[!]{Colors.RESET} Encontradas {len(exploits)} vulnerabilidades (método alternativo)")
                        else:
                            print(f"    {Colors.GREEN}[✓]{Colors.RESET} No se encontraron vulnerabilidades")
                except:
                    print(f"    {Colors.YELLOW}[*]{Colors.RESET} Método alternativo también falló")
            
            else:
                print(f"    {Colors.YELLOW}[*]{Colors.RESET} No se pudo conectar a ExploitDB (código {response.status_code})")
        
        except requests.exceptions.Timeout:
            print(f"    {Colors.YELLOW}[*]{Colors.RESET} Timeout al buscar en ExploitDB")
        except Exception as e:
            print(f"    {Colors.YELLOW}[*]{Colors.RESET} Error al buscar en ExploitDB: {str(e)}")
        
        # Guardar en cache
        self.exploitdb_cache[cache_key] = exploits
        
        return exploits
    
    def extract_cves_from_title(self, title):
        """Extrae CVEs del título del exploit"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, title, re.IGNORECASE)
        return list(set([cve.upper() for cve in cves]))  # Eliminar duplicados y normalizar

    def scan_tcp_port(self, port):
        """Escanea un puerto TCP específico"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_socket)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                sock.close()
                
                # Puerto abierto - obtener información del servicio
                service_name, version = self.identify_service_version(port, 'TCP')
                
                print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} Puerto TCP {port} ABIERTO | {service_name} | {version}")
                
                # Buscar vulnerabilidades
                exploits = self.search_exploitdb(service_name, version)
                
                with self.lock:
                    self.open_ports[port] = {
                        'protocol': 'TCP',
                        'service': service_name,
                        'version': version,
                        'exploits': exploits
                    }
            else:
                sock.close()
        except socket.timeout:
            pass  # Puerto cerrado o timeout
        except socket.error as e:
            pass  # Error de conexión
        except Exception as e:
            # Mostrar errores inesperados solo en modo debug
            pass

    def scan_udp_port(self, port):
        """Escanea un puerto UDP específico - Detecta versión y busca vulnerabilidades"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout_socket)
            
            # Enviar sonda específica según el puerto
            probe = self.get_udp_probe(port)
            sock.sendto(probe, (self.target, port))
            
            try:
                data, addr = sock.recvfrom(2048)
                # Solo si recibe respuesta está realmente abierto
                
                # Intentar identificar servicio y versión
                service_name, version = self.identify_service_version_udp(port, data)
                
                print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} Puerto UDP {port} ABIERTO | {service_name} | {version}")
                
                # Buscar vulnerabilidades
                exploits = self.search_exploitdb(service_name, version)
                
                with self.lock:
                    self.open_ports[port] = {
                        'protocol': 'UDP',
                        'service': service_name,
                        'version': version,
                        'exploits': exploits
                    }
            except socket.timeout:
                # Timeout = puerto cerrado o filtrado, NO lo agregamos
                pass
            
            sock.close()
        except Exception as e:
            pass
    
    def get_udp_probe(self, port):
        """Obtiene la sonda UDP específica según el puerto"""
        # Sondas específicas para servicios UDP comunes
        udp_probes = {
            53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS query
            123: b'\x1b' + b'\x00' * 47,  # NTP request
            161: b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
            137: b'\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01',  # NetBIOS
            1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',  # SSDP
            5353: b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',  # mDNS
        }
        
        return udp_probes.get(port, b'')  # Paquete vacío por defecto
    
    def identify_service_version_udp(self, port, response_data=None):
        """Identifica el servicio y versión en un puerto UDP"""
        service_name = self.get_service_name(port, 'udp')
        version = "Versión desconocida"
        
        # Si hay datos de respuesta, intentar parsearlos
        if response_data:
            try:
                response_str = response_data.decode('utf-8', errors='ignore').strip()
                
                # DNS (puerto 53)
                if port == 53:
                    service_name = "DNS"
                    # Intentar extraer versión de respuesta DNS
                    if len(response_data) > 12:
                        version = "DNS Server (activo)"
                
                # NTP (puerto 123)
                elif port == 123:
                    service_name = "NTP"
                    if len(response_data) >= 48:
                        # Extraer versión de NTP del byte de leap/version/mode
                        if len(response_data) > 0:
                            version_num = (response_data[0] >> 3) & 0x07
                            version = f"NTP v{version_num}"
                
                # SNMP (puerto 161)
                elif port == 161:
                    service_name = "SNMP"
                    if b'public' in response_data or b'private' in response_data:
                        # Intentar extraer versión SNMP
                        if response_data[0:2] == b'\x30':
                            if len(response_data) > 4:
                                snmp_version = response_data[4]
                                if snmp_version == 0:
                                    version = "SNMPv1"
                                elif snmp_version == 1:
                                    version = "SNMPv2c"
                                elif snmp_version == 3:
                                    version = "SNMPv3"
                                else:
                                    version = "SNMP (activo)"
                
                # NetBIOS (puerto 137)
                elif port == 137:
                    service_name = "NetBIOS-NS"
                    if len(response_data) > 0:
                        version = "NetBIOS Name Service (activo)"
                
                # SSDP (puerto 1900)
                elif port == 1900:
                    service_name = "SSDP"
                    if b'HTTP' in response_data:
                        # Extraer server info
                        for line in response_str.split('\n'):
                            if 'SERVER:' in line.upper():
                                version = line.split(':', 1)[1].strip()
                                break
                        if version == "Versión desconocida":
                            version = "SSDP/UPnP (activo)"
                
                # mDNS (puerto 5353)
                elif port == 5353:
                    service_name = "mDNS"
                    version = "Multicast DNS (activo)"
                
                # TFTP (puerto 69)
                elif port == 69:
                    service_name = "TFTP"
                    version = "Trivial FTP (activo)"
                
                # Si no se identificó por puerto específico, intentar extraer del banner
                elif response_str and version == "Versión desconocida":
                    version = self.extract_version_from_banner(response_str, service_name)
                    
            except Exception as e:
                pass
        
        # Servicios UDP conocidos por puerto (si no se detectó versión)
        if version == "Versión desconocida":
            known_udp_services = {
                53: ("DNS", "DNS Server"),
                67: ("DHCP", "DHCP Server"),
                68: ("DHCP", "DHCP Client"),
                69: ("TFTP", "Trivial File Transfer Protocol"),
                123: ("NTP", "Network Time Protocol"),
                137: ("NetBIOS-NS", "NetBIOS Name Service"),
                138: ("NetBIOS-DGM", "NetBIOS Datagram Service"),
                161: ("SNMP", "SNMP Agent"),
                162: ("SNMP-Trap", "SNMP Trap"),
                500: ("IKE", "Internet Key Exchange"),
                514: ("Syslog", "System Logging Protocol"),
                520: ("RIP", "Routing Information Protocol"),
                1194: ("OpenVPN", "OpenVPN"),
                1701: ("L2TP", "Layer 2 Tunneling Protocol"),
                1900: ("SSDP", "Simple Service Discovery Protocol"),
                4500: ("IPSec NAT-T", "IPSec NAT Traversal"),
                5353: ("mDNS", "Multicast DNS"),
            }
            
            if port in known_udp_services:
                service_name, version = known_udp_services[port]
        
        return service_name, version

    def scan_ports(self, start_port, end_port, protocol='TCP'):
        """Escanea un rango de puertos usando threads"""
        print(f"\n{Colors.BRIGHT_CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}ESCANEANDO PUERTOS {protocol}: {start_port}-{end_port}{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}Objetivo: {self.target}{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{'='*70}{Colors.RESET}\n")
        
        total_ports = end_port - start_port + 1
        print(f"{Colors.YELLOW}[*]{Colors.RESET} Escaneando {total_ports} puertos...")
        print(f"{Colors.YELLOW}[*]{Colors.RESET} Esto puede tomar varios minutos...\n")
        
        threads = []
        max_threads = 100
        
        for port in range(start_port, end_port + 1):
            if protocol == 'TCP':
                thread = threading.Thread(target=self.scan_tcp_port, args=(port,))
            else:
                thread = threading.Thread(target=self.scan_udp_port, args=(port,))
            
            threads.append(thread)
            thread.start()
            
            # Limitar número de threads concurrentes
            if len(threads) >= max_threads:
                for t in threads:
                    t.join()
                threads = []
        
        # Esperar a que terminen todos los threads
        for thread in threads:
            thread.join()
        
        print(f"\n{Colors.BRIGHT_CYAN}[✓]{Colors.RESET} Escaneo {protocol} completado")
        
        # Contar puertos encontrados
        if protocol == 'TCP':
            tcp_count = sum(1 for p in self.open_ports.values() if p['protocol'] == 'TCP')
            print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} Puertos TCP abiertos encontrados: {tcp_count}")
        else:
            udp_count = sum(1 for p in self.open_ports.values() if p['protocol'] == 'UDP')
            print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} Puertos UDP abiertos encontrados: {udp_count}")

    def show_results(self):
        """Muestra los resultados del escaneo de forma organizada"""
        if not self.open_ports:
            print(f"\n{Colors.BRIGHT_RED}[!]{Colors.RESET} No se encontraron puertos abiertos")
            return
        
        print(f"\n{Colors.BRIGHT_MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BRIGHT_MAGENTA}RESUMEN DE ESCANEO{Colors.RESET}")
        print(f"{Colors.BRIGHT_MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}Objetivo:{Colors.RESET} {self.target}")
        print(f"{Colors.BRIGHT_CYAN}SO Detectado:{Colors.RESET} {self.os_info}")
        print(f"{Colors.BRIGHT_CYAN}Total Puertos Abiertos:{Colors.RESET} {len(self.open_ports)}")
        
        # Separar puertos por protocolo
        tcp_ports = {k: v for k, v in self.open_ports.items() if v['protocol'] == 'TCP'}
        udp_ports = {k: v for k, v in self.open_ports.items() if v['protocol'] == 'UDP'}
        
        # Mostrar puertos TCP
        if tcp_ports:
            print(f"\n{Colors.BRIGHT_CYAN}PUERTOS TCP ABIERTOS:{Colors.RESET}")
            print(f"{Colors.BRIGHT_MAGENTA}{'-'*70}{Colors.RESET}")
            for port in sorted(tcp_ports.keys()):
                info = tcp_ports[port]
                print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} Puerto {port:5d} | Servicio: {info['service']:20s} | {info['version']}")
                
                if info['exploits']:
                    print(f"    {Colors.BRIGHT_RED}[!] VULNERABILIDADES ENCONTRADAS:{Colors.RESET}")
                    for idx, exploit in enumerate(info['exploits'], 1):
                        print(f"        {idx}. {exploit['title']}")
                        if exploit.get('cves'):
                            cve_list = ', '.join(exploit['cves'])
                            print(f"           {Colors.BRIGHT_YELLOW}CVEs: {cve_list}{Colors.RESET}")
                        print(f"           URL: {exploit['link']}")
        
        # Mostrar puertos UDP
        if udp_ports:
            print(f"\n{Colors.BRIGHT_CYAN}PUERTOS UDP ABIERTOS:{Colors.RESET}")
            print(f"{Colors.BRIGHT_MAGENTA}{'-'*70}{Colors.RESET}")
            for port in sorted(udp_ports.keys()):
                info = udp_ports[port]
                print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} Puerto {port:5d} | Servicio: {info['service']:20s} | {info['version']}")
                
                if info['exploits']:
                    print(f"    {Colors.BRIGHT_RED}[!] VULNERABILIDADES ENCONTRADAS:{Colors.RESET}")
                    for idx, exploit in enumerate(info['exploits'], 1):
                        print(f"        {idx}. {exploit['title']}")
                        if exploit.get('cves'):
                            cve_list = ', '.join(exploit['cves'])
                            print(f"           {Colors.BRIGHT_YELLOW}CVEs: {cve_list}{Colors.RESET}")
                        print(f"           URL: {exploit['link']}")
        
        print(f"\n{Colors.BRIGHT_MAGENTA}{'='*70}{Colors.RESET}")

    def export_results(self, filename=None):
        """Exporta los resultados a un archivo de texto"""
        if not self.open_ports:
            print(f"{Colors.YELLOW}[*]{Colors.RESET} No hay resultados para exportar")
            return
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"escaneo_{self.target}_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write("REPORTE DE ESCANEO - PysCNM 1.0\n")
                f.write("="*70 + "\n\n")
                
                f.write(f"Objetivo: {self.target}\n")
                f.write(f"Sistema Operativo: {self.os_info}\n")
                f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Puertos Abiertos: {len(self.open_ports)}\n\n")
                
                # TCP
                tcp_ports = {k: v for k, v in self.open_ports.items() if v['protocol'] == 'TCP'}
                if tcp_ports:
                    f.write("-"*70 + "\n")
                    f.write("PUERTOS TCP ABIERTOS\n")
                    f.write("-"*70 + "\n")
                    for port in sorted(tcp_ports.keys()):
                        info = tcp_ports[port]
                        f.write(f"\nPuerto: {port}\n")
                        f.write(f"  Servicio: {info['service']}\n")
                        f.write(f"  Versión: {info['version']}\n")
                        
                        if info['exploits']:
                            f.write(f"  Vulnerabilidades (ExploitDB):\n")
                            for exploit in info['exploits']:
                                f.write(f"    - {exploit['title']}\n")
                                if exploit.get('cves'):
                                    f.write(f"      CVEs: {', '.join(exploit['cves'])}\n")
                                f.write(f"      URL: {exploit['link']}\n")
                
                # UDP
                udp_ports = {k: v for k, v in self.open_ports.items() if v['protocol'] == 'UDP'}
                if udp_ports:
                    f.write("\n" + "-"*70 + "\n")
                    f.write("PUERTOS UDP ABIERTOS\n")
                    f.write("-"*70 + "\n")
                    for port in sorted(udp_ports.keys()):
                        info = udp_ports[port]
                        f.write(f"\nPuerto: {port}\n")
                        f.write(f"  Servicio: {info['service']}\n")
                        f.write(f"  Versión: {info['version']}\n")
                        
                        if info['exploits']:
                            f.write(f"  Vulnerabilidades (ExploitDB):\n")
                            for exploit in info['exploits']:
                                f.write(f"    - {exploit['title']}\n")
                                if exploit.get('cves'):
                                    f.write(f"      CVEs: {', '.join(exploit['cves'])}\n")
                                f.write(f"      URL: {exploit['link']}\n")
                
                f.write("\n" + "="*70 + "\n")
            
            print(f"\n{Colors.BRIGHT_GREEN}[+]{Colors.RESET} Resultados exportados a: {Colors.BRIGHT_CYAN}{filename}{Colors.RESET}")
        
        except Exception as e:
            print(f"{Colors.BRIGHT_RED}[!]{Colors.RESET} Error al exportar resultados: {e}")

# ===========================
# FUNCIONES AUXILIARES
# ===========================

def validate_port_range(port_range):
    """Valida y parsea un rango de puertos"""
    try:
        if '-' in str(port_range):
            start, end = port_range.split('-')
            start, end = int(start.strip()), int(end.strip())
            if start < 1 or end > 65535 or start > end:
                return None
            return start, end
        else:
            port = int(port_range)
            if port < 1 or port > 65535:
                return None
            return port, port
    except:
        return None

def get_ports_to_scan():
    """Pide al usuario el rango de puertos a escanear"""
    print(f"\n{Colors.BRIGHT_CYAN}Rangos de puertos comunes:{Colors.RESET}")
    print("  - 1-1000          (Puertos comunes)")
    print("  - 1-10000         (Escaneo más amplio)")
    print("  - 80,443          (Web)")
    print("  - 22,80,443       (SSH, HTTP, HTTPS)")
    
    while True:
        port_input = input(f"\n{Colors.BRIGHT_CYAN}Ingresa rango de puertos (ej: 1-1000 o 80): {Colors.RESET}").strip()
        
        result = validate_port_range(port_input)
        if result:
            return result[0], result[1]
        else:
            print(f"{Colors.BRIGHT_RED}[!]{Colors.RESET} Rango inválido. Intenta nuevamente.")

# ===========================
# FUNCIÓN PRINCIPAL
# ===========================

def main():
    """Función principal del programa"""
    show_banner()
    
    # Obtener objetivo
    target = input(f"{Colors.BRIGHT_CYAN}Ingresa la IP o dominio objetivo: {Colors.RESET}").strip()
    if not target:
        print(f"{Colors.BRIGHT_RED}[!]{Colors.RESET} Debes ingresar un objetivo.")
        sys.exit(1)
    
    # Crear escáner
    scanner = NetworkScanner(target)
    
    # Resolver objetivo
    if not scanner.resolve_target():
        sys.exit(1)
    
    # Detectar SO
    scanner.detect_os()
    
    # Obtener rango de puertos
    start_port, end_port = get_ports_to_scan()
    
    # Seleccionar protocolo
    while True:
        protocol = input(f"\n{Colors.BRIGHT_CYAN}¿Qué protocolo desea escanear? (tcp/udp/ambos): {Colors.RESET}").lower().strip()
        if protocol in ['tcp', 'udp', 'ambos']:
            break
        print(f"{Colors.BRIGHT_RED}[!]{Colors.RESET} Opción inválida.")
    
    # Ejecutar escaneo
    try:
        if protocol == 'tcp' or protocol == 'ambos':
            scanner.scan_ports(start_port, end_port, protocol='TCP')
        
        if protocol == 'udp' or protocol == 'ambos':
            scanner.scan_ports(start_port, end_port, protocol='UDP')
        
        # Mostrar resultados
        scanner.show_results()
        
        # Preguntar si exportar resultados
        export = input(f"\n{Colors.BRIGHT_CYAN}¿Deseas exportar los resultados? (s/n): {Colors.RESET}").lower().strip()
        if export == 's':
            scanner.export_results()
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.BRIGHT_RED}[!]{Colors.RESET} Escaneo interrumpido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.BRIGHT_RED}[!]{Colors.RESET} Error durante el escaneo: {str(e)}")
        sys.exit(1)

# ===========================
# PUNTO DE ENTRADA
# ===========================

if __name__ == "__main__":
    main()
