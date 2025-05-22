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
