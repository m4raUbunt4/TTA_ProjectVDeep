# Plan Técnico: Threat-Alert-Action (TAA)

## 1. Estructura del Script (Arquitectura)

Script único `.py` con funciones modulares. Sin clases ni OOP por simplicidad.
threat_alert_action.py
├── CONFIGURACIÓN (variables y listas editables)
├── obtener_pulses_otx() # OTX API
├── obtener_cves_recientes() # NVD API
├── enriquecer_con_vt() # VirusTotal API
├── filtrar_relevante() # Filtrado por keywords/tecnologías
├── generar_guia_accion() # Genera comandos/herramientas/pasos
├── generar_reporte() # Crea archivo .txt
└── main() # Orquesta todo

text

## 2. Manejo de API Keys

- Se leen desde **variables de entorno** (`os.getenv()`)
- Si falta `OTX_API_KEY`: error y salida
- Si falta `VT_API_KEY`: advertencia, se continúa sin enriquecimiento
- **Nunca** hardcodear claves en el script

**Uso en terminal:**
```bash
export OTX_API_KEY="tu_clave"
export VT_API_KEY="tu_clave"
python3 threat_alert_action.py
3. Manejo de Errores
Situación	Acción
Falta OTX_API_KEY	Error, salir (código 1)
Falta VT_API_KEY	Advertencia, continuar
OTX timeout/no responde	Error, continuar solo con NVD
NVD timeout/no responde	Error, continuar solo con OTX
Ambas fuentes fallan	Error, salir
Rate limit alcanzado	Esperar 60s, reintentar 1 vez
Todo el código va dentro de bloques try/except.

4. Formato de Salida
Dos salidas:

Pantalla (stdout): Resumen de ejecución

text
✅ Conectado a OTX: 45 pulses obtenidos
✅ Conectado a NVD: 12 CVEs críticos encontrados
🔍 Filtrando... 8 amenazas relevantes
📄 Reporte guardado: reporte_2026-05-13.txt
Archivo de texto: reporte_YYYY-MM-DD.txt

Mismo directorio del script

Formato detallado según spec.md

5. Configuración Externa
MVP (fase inicial): Keywords y tecnologías como listas dentro del script (sección CONFIGURACIÓN).

Futuro: Archivo config.json externo.

Listas iniciales:

python
PALABRAS_CLAVE = [
    "zero day", "ransomware", "sector bancario",
    "latinamerica", "méxico", "mexico"
]

TECNOLOGIAS = [
    "windows server", "linux", "unix", "kubernetes",
    "aws", "gcp", "vps", "vpn", "fortinet", "paloalto"
]
6. Dependencias
Librería	Instalación	¿Nativa?
requests	pip3 install requests	No
json	-	Sí
datetime	-	Sí
os	-	Sí
7. Limitaciones Técnicas
Rate limiting: Respetar límites gratis

OTX: 1 solicitud/segundo (cortesía)

NVD: 5 solicitudes/30 segundos

VirusTotal: 4 solicitudes/minuto

Volumen máximo por ejecución:

100 pulses de OTX

50 CVEs

Tiempo estimado: < 2 minutos

8. Pruebas (Verificación Manual)
Ejecución real con API keys propias

Verificar que genera el archivo de reporte

Validar formato visual del reporte

9. Ejecución en Mac
bash
# 1. Exportar claves
export OTX_API_KEY="tu_clave"
export VT_API_KEY="tu_clave"

# 2. Ir a la carpeta del script
cd ~/Documentos/Threat-Alert-Action/

# 3. Ejecutar
python3 threat_alert_action.py

# 4. Ver reporte
cat reporte_*.txt
# o
open reporte_*.txt
10. Criterios de Éxito del Plan
El script se ejecuta sin errores con las API keys configuradas

Las funciones son modulares y reutilizables

Los errores de red/API no crashean el script

El reporte generado es legible y útil

La ejecución completa toma menos de 2 minutos