import re
import requests
import time
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

# Configuración del tema visual general
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Pon aquí tu API Key de VirusTotal entre las comillas
API_KEY = "poner tu API KEY"

def extraer_ips_del_log(log_file):
    ips_detectadas = set()
    
    # Expresión regular robusta que valida octetos matemáticos del 0 al 255
    patron_ip = re.compile(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as file:
            for linea in file:
                ips_encontradas = patron_ip.findall(linea)
                for ip in ips_encontradas:
                    # Filtramos rangos locales y broadcasts comunes
                    if not ip.startswith("192.168.") and not ip.startswith("127.") and not ip.endswith(".255"):
                        ips_detectadas.add(ip)
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo leer el archivo: {str(e)}")
        
    # Límite máximo de IPs únicas a analizar por archivo
    return list(ips_detectadas)[:100]

def consultar_reputacion_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            datos = response.json()
            maliciosos = datos['data']['attributes']['last_analysis_stats']['malicious']
            harmless = datos['data']['attributes']['last_analysis_stats']['harmless']
            return {"ip": ip, "maliciosa": maliciosos, "segura": harmless}
        elif response.status_code == 429:
            return {"ip": ip, "error": "Límite de API excedido (Error 429). Ralentizando..."}
        else:
            return {"ip": ip, "error": f"Error API Código {response.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

# --- Controladores de la interfaz ---
ruta_archivo = ""

def seleccionar_archivo():
    global ruta_archivo
    file_path = filedialog.askopenfilename(
        title="Seleccionar archivo de Logs o PCAP",
        filetypes=[("Archivos de log/texto", "*.log *.txt"), ("Todos los archivos", "*.*")]
    )
    if file_path:
        ruta_archivo = file_path
        lbl_archivo.configure(text=f"📦 Archivo cargado: {file_path.split('/')[-1]}", text_color="#2ecc71")
        btn_escanear.configure(state="normal", fg_color="#1f538d")

# Esta función se ejecuta en segundo plano en un hilo secundario
def proceso_escaneo_background():
    txt_resultados.configure(state="normal")
    txt_resultados.delete("1.0", ctk.END)
    txt_resultados.insert(ctk.END, "[*] Analizando archivo y extrayendo IPs válidas...\n")
    
    lista_ips = extraer_ips_del_log(ruta_archivo)
    txt_resultados.insert(ctk.END, f"[+] Se han aislado {len(lista_ips)} IPs externas únicas.\n")
    txt_resultados.insert(ctk.END, "[!] Iniciando escaneo continuo (pausa de 16s entre consultas para respetar la API gratuita).\n\n")
    
    # NUEVO: Inicializamos el contador de alertas
    contador_alertas = 0
    
    for indice, ip in enumerate(lista_ips):
        txt_resultados.insert(ctk.END, f"[*] [{indice + 1}/{len(lista_ips)}] Consultando VirusTotal para: {ip}...\n")
        txt_resultados.see(ctk.END)
        
        res = consultar_reputacion_ip(ip)
        
        if "error" in res:
            txt_resultados.insert(ctk.END, f"[-] IP: {res['ip']} -> {res['error']}\n\n")
        else:
            if res['maliciosa'] > 0:
                # Alerta Maliciosa pintada en rojo
                status = f"🚨 ALERTA MALICIOSA ({res['maliciosa']} reportes)"
                mensaje_linea = f"[{status}] IP: {res['ip']} | Motores Limpios: {res['segura']}\n\n"
                txt_resultados.insert(ctk.END, mensaje_linea, tags="peligro")
                
                # NUEVO: Sumamos 1 al contador si es maliciosa
                contador_alertas += 1
            else:
                # Tráfico Seguro pintado en verde lima
                status = "🟢 Tráfico Seguro"
                mensaje_linea = f"[{status}] IP: {res['ip']} | Motores Limpios: {res['segura']}\n\n"
                txt_resultados.insert(ctk.END, mensaje_linea, tags="seguro")
        
        txt_resultados.see(ctk.END)
        
        # Si todavía quedan más IPs por procesar, hacemos la pausa de seguridad
        if indice < len(lista_ips) - 1:
            txt_resultados.insert(ctk.END, "⏳ Esperando 16 segundos para la próxima consulta...\n")
            txt_resultados.see(ctk.END)
            time.sleep(16)
        
    # NUEVO: Mensaje de cierre personalizado que muestra el total
    txt_resultados.insert(ctk.END, "="*60 + "\n")
    txt_resultados.insert(ctk.END, "  ANÁLISIS DE AMENAZAS COMPLETADO CON ÉXITO\n")
    
    if contador_alertas > 0:
        resumen_msg = f"  👉 TOTAL DE ALERTAS MALICIOSAS DETECTADAS: {contador_alertas}\n"
        txt_resultados.insert(ctk.END, resumen_msg, tags="peligro")
    else:
        resumen_msg = "  👉 ENHORABUENA: No se han detectado amenazas en este log.\n"
        txt_resultados.insert(ctk.END, resumen_msg, tags="seguro")
        
    txt_resultados.insert(ctk.END, "="*60 + "\n")
    
    txt_resultados.see(ctk.END)
    txt_resultados.configure(state="disabled")
    btn_escanear.configure(state="normal")
    btn_cargar.configure(state="normal")

def iniciar_escaneo():
    if not ruta_archivo:
        messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo primero.")
        return
    
    btn_escanear.configure(state="disabled")
    btn_cargar.configure(state="disabled")
    
    hilo_escaneo = threading.Thread(target=proceso_escaneo_background)
    hilo_escaneo.daemon = True
    hilo_escaneo.start()

# --- Construcción de la Interfaz Gráfica ---
window = ctk.CTk()
window.title("Analizador de Amenazas - Cyber Threat Intelligence")
window.geometry("700x580")
window.resizable(False, False)

# Encabezado Principal
lbl_titulo = ctk.CTkLabel(window, text="ANALIZADOR DE LOGS DE RED", font=ctk.CTkFont(family="Helvetica", size=22, weight="bold"))
lbl_titulo.pack(pady=(25, 5))

lbl_subtitulo = ctk.CTkLabel(window, text="Cyber Threat Intelligence & Traffic Analysis Tool", font=ctk.CTkFont(family="Helvetica", size=12, slant="italic"), text_color="#7f8c8d")
lbl_subtitulo.pack(pady=(0, 20))

# Contenedor de Botones (Frame)
frame_controles = ctk.CTkFrame(window, corner_radius=10)
frame_controles.pack(pady=10, padx=30, fill="x")

btn_cargar = ctk.CTkButton(frame_controles, text="📂 Subir Archivo Log", font=ctk.CTkFont(size=13, weight="bold"), command=seleccionar_archivo, height=40)
btn_cargar.grid(row=0, column=0, padx=20, pady=15, sticky="ew")

btn_escanear = ctk.CTkButton(frame_controles, text="⚡ Escanear Amenazas", font=ctk.CTkFont(size=13, weight="bold"), command=iniciar_escaneo, state="disabled", fg_color="#34495e", height=40)
btn_escanear.grid(row=0, column=1, padx=20, pady=15, sticky="ew")

frame_controles.grid_columnconfigure(0, weight=1)
frame_controles.grid_columnconfigure(1, weight=1)

# Estado del archivo cargado
lbl_archivo = ctk.CTkLabel(window, text="Ningún archivo seleccionado", font=ctk.CTkFont(size=12))
lbl_archivo.pack(pady=5)

# Título de la sección de salida
lbl_res_titulo = ctk.CTkLabel(window, text="Resultados del Análisis en Tiempo Real:", font=ctk.CTkFont(size=13, weight="bold"))
lbl_res_titulo.pack(anchor="w", padx=35, pady=(15, 5))

# Cuadro de texto principal para logs
txt_resultados = ctk.CTkTextbox(window, width=640, height=260, font=ctk.CTkFont(family="Consolas", size=11), text_color="#e0e0e0", fg_color="#111111", border_width=1, border_color="#2c3e50")
txt_resultados.pack(padx=30, pady=5)
txt_resultados.configure(state="disabled")

# --- Inyección de estilos de color en el backend nativo de la consola ---
txt_resultados._textbox.tag_config("seguro", foreground="#00FF00")  # Verde Lima
txt_resultados._textbox.tag_config("peligro", foreground="#FF3333")  # Rojo Intenso

window.mainloop()