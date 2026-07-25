# cti-log-analyzer
Herramienta en Python con interfaz gráfica (CustomTkinter) para el análisis de reputación de IPs en logs de tráfico web mediante la API de VirusTotal.
# Analizador de Logs de Red - Threat Intelligence Tool (CTI)

Herramienta gráfica desarrollada en Python orientada a analistas de seguridad en entornos **SOC** y **Blue Team**. Automatiza el análisis de reputación de direcciones IP en logs de tráfico web (por ejemplo, generados con **Burp Suite**), conectándose en tiempo real con la API de **VirusTotal**.
![Demostración de la aplicación](demo.png)

## 🚀 Características Principales
* **Extracción Precisa:** Expresión regular matemática avanzada para validar octetos IPv4 reales (del 0 al 255), descartando rangos locales (`192.168.x.x`, `127.x.x.x`) y filtrando falsos positivos.
* **Control de API Rate Limits:** Arquitectura multihilo (*Threading*) con pausa programada de 16 segundos entre consultas para respetar los límites de la API gratuita sin congelar la interfaz de usuario.
* **Consola de Monitorización Estilizada:** Output visual interactivo desarrollado en **CustomTkinter** con código de colores (Verde para tráfico seguro, Rojo para alertas maliciosas).
* **Resumen de Amenazas:** Conteo automatizado del total de alertas maliciosas detectadas al finalizar el análisis.

## 🛠️ Tecnologías Utilizadas
* **Lenguaje:** Python 3
* **Interfaz Gráfica:** CustomTkinter / Tkinter
* **Módulos:** `requests` (API REST), `re` (Regex), `threading` (Concurrencia)

## 📋 Requisitos e Instalación

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/benito-fernandez-cyber/cti-log-analyzer.git

   Instalar las dependencias necesarias:
   pip install customtkinter requests

   Añadir una API Key válida de VirusTotal en la variable API_KEY del archivo scanner.py.

Ejecutar la aplicación
python scanner.py
