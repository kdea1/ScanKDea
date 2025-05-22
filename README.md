# ScanKDea
# 🔥 ScanKDea - Advanced Recon Tool

![Banner](assets/banner.png) <!-- Puedes añadir una imagen si lo deseas -->

**ScanKDea** es un escáner de seguridad avanzado en Python diseñado para profesionales de ciberseguridad y auditorías éticas. Ofrece capacidades de escaneo de puertos, detección de servicios, fingerprinting de sistemas operativos y análisis de vulnerabilidades básico.

## 🚀 Características Principales

- Escaneo de puertos rápido y eficiente con múltiples técnicas:
  - TCP Connect (predeterminado)
  - SYN Scan (simulado)
  - UDP Scan
  - Modo Stealth (escaneo sigiloso)
  - Escaneo completo (TCP+UDP)
- Detección automática de servicios comunes
- Grabación de banners de servicios
- Detección de sistema operativo basada en firmas
- Escaneo de rangos de IP (CIDR) y listas de puertos
- Salida colorida y formato tabular
- Estadísticas detalladas del escaneo
- Multi-threading para escaneos rápidos

## 📦 Instalación

1. Requisitos:
   - Python 3.6+
   - Recomendado: Linux/macOS (para mejores resultados)

2. Instalar dependencias:
```bash
pip install colorama
Clonar repositorio:

bash
git clone https://github.com/tuusuario/scankdea.git
cd scankdea
Ejecutar:

bash
python scankdea.py --help
🛠 Uso Básico
bash
# Escaneo simple a un objetivo
python scankdea.py 192.168.1.1

# Escaneo con puertos específicos
python scankdea.py example.com -p 80,443,8080

# Escaneo de rango de puertos con más hilos
python scankdea.py 192.168.1.0/24 -p 1-1024 -t 200

# Escaneo sigiloso (stealth) con timeout personalizado
python scankdea.py 10.0.0.1 -m stealth -to 0.5

# Modo verboso para ver detalles
python scankdea.py target.com -v
📊 Opciones Disponibles
Opción	Descripción	Valor por defecto
target	IP, hostname o rango CIDR a escanear	Requerido
-p, --ports	Puertos a escanear (ej: 80,443 o 1-1000)	1-1000
-t, --threads	Número de hilos a utilizar	100
-to, --timeout	Timeout en segundos para conexiones	1.0
-v, --verbose	Modo verboso para más detalles	False
-m, --method	Método de escaneo [tcp_connect, syn, udp, stealth]	tcp_connect
--help	Muestra mensaje de ayuda	
📝 Ejemplos Avanzados
bash
# Escaneo completo (TCP+UDP) a red corporativa
python scankdea.py 10.10.0.0/24 -p 1-65535 -m full -t 300

# Exportar resultados a JSON
python scankdea.py 192.168.1.100 -p 1-10000 > resultados.json

# Escaneo rápido de puertos comunes en múltiples hosts
python scankdea.py 192.168.1.1,192.168.1.2,192.168.1.3 -p 21,22,80,443,445,3389
⚠️ DISCLAIMER LEGAL IMPORTANTE
ScanKDea es una herramienta diseñada exclusivamente para pruebas de seguridad legales y auditorías éticas.

🚨 ADVERTENCIA: El uso no autorizado de esta herramienta contra sistemas informáticos sin permiso explícito es ILEGAL y constituye una violación de las leyes de ciberseguridad en la mayoría de países.

El desarrollador y colaboradores NO se hacen responsables del mal uso de esta herramienta. ScanKDea debe usarse únicamente bajo las siguientes condiciones:

En sistemas de tu propiedad

Con autorización escrita del propietario del sistema

En entornos de prueba controlados

Cumpliendo todas las leyes locales y regulaciones aplicables

RECUERDA: Siempre obtén permiso por escrito antes de realizar cualquier prueba de seguridad.

📜 Licencia
Este proyecto está bajo licencia MIT - ver el archivo LICENSE para más detalles.

🤝 Contribuciones
Las contribuciones son bienvenidas. Por favor abre un Issue o Pull Request para sugerencias y mejoras.

🛡️ Desarrollado con fines educativos por la Comunidad HackingTeam 🛡️


Este README incluye:

1. **Descripción clara** de la herramienta
2. **Instalación** sencilla
3. **Ejemplos de uso** desde básico hasta avanzado
4. **Opciones detalladas** en formato de tabla
5. **Disclaimer legal prominente** para uso ético
6. **Sección de licencia** y contribuciones

Puedes personalizar las secciones según necesites, especialmente:
- Añadir capturas de pantalla
- Incluir más ejemplos específicos
- Agregar sección de changelog
- Añadir tu información de contacto

El disclaimer está destacado para cumplir con requisitos legales y éticos, crucial para herramientas de seguridad.
