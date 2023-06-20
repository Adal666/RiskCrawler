import tkinter as tk
from tkinter import filedialog
from bs4 import BeautifulSoup
from openpyxl import Workbook
import requests
import re

def obtener_urls_desde_pagina(url_pagina):
    # Realizar la solicitud GET a la página
    response = requests.get(url_pagina)

    # Crear el objeto BeautifulSoup
    soup = BeautifulSoup(response.content, "html.parser")

    # Encontrar todos los elementos 'a' con la clase 'external-link'
    enlaces = soup.find_all("a", class_="external-link")

    # Obtener las URLs de los enlaces con comillas dobles
    urls = [enlace["href"] for enlace in enlaces]

    # Filtrar las URLs y mantener solo las de vulnerabilidades
    urls_vulnerabilidades = []
    for url in urls:
        if url.startswith("https://nvd.nist.gov/vuln/detail/"):
            urls_vulnerabilidades.append(url)

    return urls_vulnerabilidades

def generar_archivo():
    # Obtener la URL ingresada por el usuario
    url_pagina = url_entry.get()

    # Obtener las URLs de los enlaces desde la página
    urls = obtener_urls_desde_pagina(url_pagina)

    # Crear un nuevo archivo de Excel
    workbook = Workbook()
    sheet = workbook.active

    # Escribir las URLs en filas sucesivas
    for url in urls:
        sheet.append([url])

    # Abrir el diálogo de guardado de archivo
    file_path = filedialog.asksaveasfilename(defaultextension=".xlsx")

    # Guardar el archivo de Excel
    workbook.save(file_path)

    # Mostrar mensaje de éxito
    result_label.config(text="Archivo generado exitosamente.")

# Crear la ventana principal
window = tk.Tk()
window.title("Generador de Archivo .XLSX")

# Crear etiqueta y campo de entrada para la URL
url_label = tk.Label(window, text="URL de la página:")
url_label.pack()
url_entry = tk.Entry(window)
url_entry.pack()

# Crear botón para generar el archivo
generate_button = tk.Button(window, text="Generar archivo", command=generar_archivo)
generate_button.pack()

# Crear etiqueta para mostrar el resultado
result_label = tk.Label(window, text="")
result_label.pack()

# Ejecutar el bucle principal de la interfaz
window.mainloop()


import requests
from bs4 import BeautifulSoup
from openpyxl import Workbook
from tkinter import Tk, Button, Text, filedialog

def obtener_informacion_cve(url):
    # Realizar la solicitud GET a la URL
    response = requests.get(url)

    # Crear el objeto BeautifulSoup
    soup = BeautifulSoup(response.content, "html.parser")

    # Obtener la descripción
    description_element = soup.find("p", attrs={"data-testid": "vuln-description"})
    if description_element is not None:
        description = description_element.text.strip()
    else:
        description = "No se encontró la descripción"

    # Obtener la fecha
    fecha_element = soup.find("span", {"data-testid": "vuln-published-on"})
    if fecha_element is not None:
        fecha = fecha_element.text.strip()
    else:
        fecha = "No se encontró la fecha"

    base_score_element = soup.find("a", attrs={"data-testid": "vuln-cvss3-cna-panel-score"})
    if base_score_element is not None:
        base_score = base_score_element.text.strip()
    else:
        base_score_element = soup.find("a", class_="label-critical")
        if base_score_element is not None:
            base_score = base_score_element.text.strip()
        else:
            base_score_element = soup.find("a", string="9.8 CRITICAL")
            if base_score_element is not None:
                base_score = base_score_element.text.strip()
            else:
                pattern = re.compile(r"\d+\.\d+\s+CRITICAL")
                base_score_element = soup.find("a", string=pattern)
                if base_score_element is not None:
                    base_score = base_score_element.text.strip()
                else:
                    base_score = "not yet assigned"

    # Eliminar las palabras como "CRITICAL", "HIGH", "MEDIUM" y "LOW" del base score (nueva modificación)
    base_score = re.sub(r'\b(CRITICAL|HIGH|MEDIUM|LOW)\b', '', base_score).strip()

    # Si no se encontró ningún valor, mostrar "not yet assigned" en su lugar (nueva modificación)
    if not base_score:
        base_score = "not yet assigned"


    # Obtener el ID de la vulnerabilidad
    vuln_id_element = soup.find("span", {"data-testid": "page-header-vuln-id"})
    if vuln_id_element is not None:
        vuln_id = vuln_id_element.text.strip()
    else:
        vuln_id = "No se encontró el ID de la vulnerabilidad"
    
    # Obtener el vendor
    vendor_element = soup.find("span", {"class": "wrapData", "data-testid": "vuln-cvss3-source-cna"})
    if vendor_element is not None:
        vendor = vendor_element.text.strip()
    else:
        vendor = "No se encontró el Vendor"

    # Crear el diccionario con los resultados
    resultado = {
        "Descripción": description,
        "Fecha": fecha,
        "Base Score": base_score,
        "Vendor": vendor,
        "Vulnerability ID": vuln_id
    }

    return resultado

def procesar_urls():
    # Obtener los URLs ingresados por el usuario
    urls = url_text.get("1.0", "end").strip().splitlines()

    # Filtrar las URLs y mantener solo las de vulnerabilidades
    urls_vulnerabilidades = []
    for url in urls:
        if url.startswith("https://nvd.nist.gov/vuln/detail/"):
            urls_vulnerabilidades.append(url)

    # Crear un nuevo archivo de Excel
    workbook = Workbook()
    sheet = workbook.active

    # Escribir los encabezados en la primera fila
    encabezados = ["Descripción", "Fecha", "Base Score", "Vendor", "Vulnerability ID"]
    sheet.append(encabezados)

    # Procesar cada URL y escribir los resultados en filas sucesivas
    for url in urls_vulnerabilidades:
        # Eliminar las comillas dobles si están presentes
        url = url.strip('"')

        resultado = obtener_informacion_cve(url)

        # Agregar " MISC" a los números CVE (nueva modificación)
        vulnerability_id = resultado["Vulnerability ID"]
        if vulnerability_id.startswith("CVE"):
            vulnerability_id += " MISC"

        fila_resultado = [
            resultado["Descripción"],
            resultado["Fecha"],
            resultado["Base Score"],
            resultado["Vendor"],
            vulnerability_id
        ]
        sheet.append(fila_resultado)

    # Mostrar un cuadro de diálogo para guardar el archivo de Excel
    file_path = filedialog.asksaveasfilename(
        defaultextension=".xlsx",
        filetypes=[("Excel Files", "*.xlsx")]
    )

    if file_path:
        # Guardar el archivo de Excel
        workbook.save(file_path)

# Crear la ventana de la interfaz gráfica
window = Tk()
window.title("Web Scraping de CVEs")
window.geometry("500x300")

# Texto de entrada para las URLs
url_text = Text(window, height=10, width=50)
url_text.pack()

# Botón para iniciar el proceso
procesar_button = Button(window, text="Procesar URLs", command=procesar_urls)
procesar_button.pack()

# Ejecutar el bucle de eventos de la interfaz gráfica
window.mainloop()
