# PysCNM 1.0 - Python Security Network Monitor

<div align="center">

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗ ██╗   ██╗███████╗ ██████╗███╗   ██╗███╗   ███╗  ║
║   ██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝████╗  ██║████╗ ████║  ║
║   ██████╔╝ ╚████╔╝ ███████╗██║     ██╔██╗ ██║██╔████╔██║  ║
║   ██╔═══╝   ╚██╔╝  ╚════██║██║     ██║╚██╗██║██║╚██╔╝██║  ║
║   ██║        ██║   ███████║╚██████╗██║ ╚████║██║ ╚═╝ ██║  ║
║   ╚═╝        ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═══╝╚═╝     ╚═╝  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

**Escáner de Red Avanzado con Detección de Vulnerabilidades**

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![ExploitDB](https://img.shields.io/badge/ExploitDB-Integrated-red)](https://www.exploit-db.com/)

[Características](#características) • [Instalación](#instalación) • [Uso](#uso) • [Ejemplos](#ejemplos) • [Documentación](#documentación)

</div>

---

## 📋 Descripción

**PysCNM** (Python Security Network Monitor) es un escáner de red avanzado diseñado para profesionales de seguridad, administradores de sistemas y entusiastas de la ciberseguridad. Combina escaneo de puertos, detección de servicios/versiones y búsqueda automática de vulnerabilidades en la base de datos de ExploitDB.

## ✨ Características

### 🔍 Escaneo Completo
- ✅ **Escaneo TCP/UDP** - Soporte para ambos protocolos
- ✅ **Multithreading** - Escaneo rápido con hasta 100 threads concurrentes
- ✅ **Detección de SO** - Identificación automática del sistema operativo objetivo
- ✅ **Banner Grabbing** - Captura de banners de servicios para identificación

### 🎯 Detección de Servicios
- ✅ **Identificación de Servicios** - Detecta qué servicio corre en cada puerto
- ✅ **Detección de Versiones** - Extrae versiones específicas de:
  - Servidores web (Apache, Nginx, IIS)
  - SSH (OpenSSH)
  - FTP, SMTP, MySQL, PostgreSQL
  - DNS, NTP, SNMP (UDP)
  - Y más...

### 🔐 Análisis de Vulnerabilidades
- ✅ **Integración con ExploitDB** - Búsqueda automática en la base de datos de ExploitDB
- ✅ **Detección de CVEs** - Identifica CVEs asociados a cada servicio
- ✅ **Links Directos** - Proporciona URLs directas a exploits y documentación
- ✅ **Cache Inteligente** - Evita búsquedas duplicadas para mayor velocidad

### 📊 Reportes
- ✅ **Salida Colorizada** - Interfaz de terminal clara y organizada
- ✅ **Exportación a TXT** - Guarda resultados en formato de texto estructurado
- ✅ **Información Detallada** - Incluye puertos, servicios, versiones, CVEs y exploits

## 🚀 Instalación

### Requisitos Previos

- Python 3.7 o superior
- pip (gestor de paquetes de Python)
- Conexión a Internet (para búsqueda de vulnerabilidades)

### Dependencias

```bash
# Instalar dependencias requeridas
pip install requests beautifulsoup4
```

### Instalación Rápida

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/pyscnm.git

# Navegar al directorio
cd pyscnm

# Instalar dependencias
pip install -r requirements.txt

# Dar permisos de ejecución (Linux/Mac)
chmod +x pyscnm1_0_mejorado.py

# Ejecutar
python3 pyscnm1_0_mejorado.py
```

## 💻 Uso

### Uso Básico

```bash
python3 pyscnm1_0_mejorado.py
```

El script te guiará a través de un proceso interactivo donde deberás proporcionar:

1. **IP o Dominio objetivo** (ej: `192.168.1.1` o `example.com`)
2. **Rango de puertos** (ej: `1-1000`, `80-443`, o `80`)
3. **Protocolo** (`tcp`, `udp`, o `ambos`)

### Rangos de Puertos Comunes

| Rango | Descripción |
|-------|-------------|
| `1-1000` | Puertos más comunes (rápido) |
| `1-65535` | Todos los puertos (muy lento) |
| `80,443` | Puertos web específicos |
| `20-25` | Rango personalizado |
| `80` | Puerto único |

## 📸 Ejemplos

### Ejemplo 1: Escaneo Básico TCP

```bash
$ python3 pyscnm1_0_mejorado.py

Ingresa la IP o dominio objetivo: 192.168.1.100
Dominio resuelto: 192.168.1.100

Ingresa rango de puertos (ej: 1-1000 o 80): 1-1000
¿Qué protocolo desea escanear? (tcp/udp/ambos): tcp

======================================================================
ESCANEANDO PUERTOS TCP: 1-1000
======================================================================

[+] Puerto TCP    22 ABIERTO | ssh | OpenSSH 8.2p1 Ubuntu
    [*] Buscando vulnerabilidades para: ssh OpenSSH 8.2p1 Ubuntu
    [!] Encontradas 2 vulnerabilidades
    
[+] Puerto TCP    80 ABIERTO | http | Apache/2.4.41 (Ubuntu)
    [*] Buscando vulnerabilidades para: http Apache/2.4.41
    [!] Encontradas 3 vulnerabilidades
```

### Ejemplo 2: Resultado con CVEs

```bash
PUERTOS TCP ABIERTOS:
----------------------------------------------------------------------
[+] Puerto    80 | Servicio: http                 | Apache/2.4.49
    [!] VULNERABILIDADES ENCONTRADAS:
        1. Apache HTTP Server 2.4.49 - Path Traversal & RCE
           CVEs: CVE-2021-41773, CVE-2021-42013
           URL: https://www.exploit-db.com/exploits/50383
        2. Apache 2.4.50 - Remote Code Execution
           CVEs: CVE-2021-42013
           URL: https://www.exploit-db.com/exploits/50512
```

### Ejemplo 3: Exportar Resultados

```bash
¿Deseas exportar los resultados? (s/n): s
[+] Resultados exportados a: escaneo_192.168.1.100_20250213_143052.txt
```

## 📁 Estructura del Proyecto

```
pyscnm/
├── pyscnm1_0_mejorado.py          # Script principal
├── README.md                       # Este archivo
├── requirements.txt                # Dependencias Python
├── LICENSE                         # Licencia MIT
├── docs/
│   ├── EXPLOITDB_API_DOCUMENTATION.md
│   └── exploitdb_api_example.json
└── examples/
    └── escaneo_ejemplo.txt         # Ejemplo de reporte exportado
```

## 🔧 Configuración Avanzada

### Ajustar Timeouts

Edita el archivo `pyscnm1_0_mejorado.py` y modifica la línea:

```python
self.timeout_socket = 3  # Cambiar a 5 para redes lentas
```

### Modificar Número de Threads

```python
max_threads = 100  # Cambiar a 50 para sistemas con menos recursos
```

### Personalizar Búsqueda de ExploitDB

El script usa la API pública de ExploitDB. Puedes ajustar el número de resultados en:

```python
for row in rows[:5]:  # Cambiar 5 por el número deseado
```

## 📖 Documentación de la API

Para más información sobre la integración con ExploitDB, consulta:
- [Documentación de ExploitDB API](docs/EXPLOITDB_API_DOCUMENTATION.md)
- [Ejemplo de Respuesta JSON](docs/exploitdb_api_example.json)

## ⚠️ Advertencias de Seguridad

### ⚖️ Uso Ético y Legal

Este script es una herramienta educativa y de auditoría de seguridad. **SOLO** debe usarse en:

- ✅ Sistemas de tu propiedad
- ✅ Redes para las que tienes autorización explícita
- ✅ Entornos de prueba y laboratorios
- ✅ Programas de bug bounty autorizados

**❌ NO usar para:**

- Escanear redes sin autorización
- Actividades ilegales o maliciosas
- Pruebas sin consentimiento del propietario
- Violación de términos de servicio

> **IMPORTANTE**: El uso no autorizado de este software puede ser ilegal en tu jurisdicción. El autor no se hace responsable del mal uso de esta herramienta.

### 🛡️ Responsabilidad

- Siempre obtén autorización por escrito antes de escanear
- Respeta las políticas de seguridad de las organizaciones
- Reporta vulnerabilidades de forma responsable
- Cumple con las leyes locales de ciberseguridad

## 🐛 Solución de Problemas

### Error: "No se pudo conectar a ExploitDB (código 500)"

**Solución**: El servidor de ExploitDB puede estar temporalmente saturado. El script automáticamente intenta con un método alternativo.

### Error: "No se encontraron puertos abiertos"

**Causas posibles:**
1. El objetivo no está accesible (ping, firewall)
2. Todos los puertos están cerrados
3. Timeout muy bajo para la red

**Solución**: Aumenta el timeout o verifica conectividad con `ping`.

### No detecta versiones de servicios

**Solución**: Algunos servicios no exponen su versión fácilmente. El script intentará identificar por puerto conocido.

### Escaneo muy lento

**Solución**: 
1. Reduce el rango de puertos
2. Escanea solo TCP (UDP es más lento)
3. Aumenta el número de threads (si tu sistema lo permite)

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Si deseas mejorar PysCNM:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### Áreas de Mejora

- [ ] Soporte para escaneo IPv6
- [ ] Detección de versiones más precisa
- [ ] Integración con otras bases de datos de vulnerabilidades (NVD, CVE)
- [ ] Exportación en formatos JSON/XML/HTML
- [ ] Modo stealth/sigiloso
- [ ] GUI opcional

## 📜 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## 👨‍💻 Autor

**G. Zaballa**

- GitHub: [@tu-usuario](https://github.com/tu-usuario)
- Email: tu-email@ejemplo.com

## 🙏 Agradecimientos

- [ExploitDB](https://www.exploit-db.com/) por su invaluable base de datos de exploits
- Comunidad de seguridad informática
- Contribuidores y testers

## 📚 Referencias

- [ExploitDB](https://www.exploit-db.com/)
- [CVE Database](https://cve.mitre.org/)
- [OWASP](https://owasp.org/)
- [Python Socket Documentation](https://docs.python.org/3/library/socket.html)

## 📊 Roadmap

### Version 1.0 (Actual)
- ✅ Escaneo TCP/UDP
- ✅ Detección de versiones
- ✅ Integración ExploitDB
- ✅ Detección de CVEs

### Version 1.1 (Planificada)
- [ ] Exportación JSON/XML
- [ ] Modo verbose/debug
- [ ] Escaneo de rangos de IPs
- [ ] Rate limiting configurable

### Version 2.0 (Futuro)
- [ ] GUI con Tkinter/Qt
- [ ] Integración con NIST NVD
- [ ] Análisis de vulnerabilidades avanzado
- [ ] Base de datos local de resultados

---

<div align="center">

**⭐ Si este proyecto te resulta útil, considera darle una estrella ⭐**

Made with ❤️ for the security community

</div>
