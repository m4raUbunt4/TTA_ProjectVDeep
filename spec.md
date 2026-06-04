# Especificación del Proyecto: Threat-Alert-Action (TAA)

## 1. Objetivo Estratégico

Desarrollar una herramienta CLI (para ejecución manual diaria) que consolide inteligencia de amenazas de múltiples fuentes (OTX, CVE/NVD, VirusTotal, y futuras), filtre por relevancia al contexto empresarial de Latinoamérica/sector bancario, y genere un reporte ejecutivo+técnico con guías de acción concretas para equipos de seguridad, threat hunting y pentesting.

## 2. Alcance (MVP - Producto Mínimo Viable)

### Fuentes de datos (fase 1)
- [ ] AlienVault OTX (Pulses con contexto)
- [ ] NVD/CVE (vulnerabilidades con CVSS)
- [ ] VirusTotal (enriquecimiento de IoCs)

### Fuentes futuras (arquitectura preparada para extender)
- [ ] The Cyber Security Hub (RSS/noticias)
- [ ] Otras definidas por el usuario

### Salida esperada
- Archivo de texto plano (`reporte_YYYY-MM-DD.txt`) que pueda convertirse a PDF.
- Contenido estructurado en tres secciones principales:
  - **Ejecutivo:** Resumen de amenazas críticas, impacto potencial, resumen de IoCs.
  - **Técnico:** Detalle por amenaza (ID, score, descripción, enlaces).
  - **Acción:** Guía de pruebas (comandos, herramientas, pasos manuales).

## 3. Criterios de Filtrado (Relevancia Empresarial)

Una amenaza es **relevante** si cumple AL MENOS UNO de estos criterios:

| Categoría | Criterios (match case-insensitive) |
|:---|:---|
| **Palabras clave** | `zero day`, `ransomware`, `sector bancario`, `latinamerica`, `méxico` |
| **Severidad** | CVSS v3 >= 7.6 (High o Critical) |
| **Tecnologías objetivo** | `windows server`, `linux`, `unix`, `kubernetes`, `aws`, `gcp`, `vps`, `vpn`, `fortinet`, `paloalto` |

*Nota: El usuario podrá modificar esta lista en un archivo de configuración.*

## 4. Estructura del Reporte (por amenaza filtrada)

Para cada amenaza que pase el filtro, el reporte incluirá:

### 4.1 Cabecera de la amenaza
- **ID** (CVE-XXXX-XXXX o Pulse ID de OTX)
- **Título** (nombre del Pulse o resumen del CVE)
- **Fecha de publicación**
- **Severidad** (CVSS score + vector)
- **Palabras clave que activaron el filtro**

### 4.2 Resumen ejecutivo (máx 3 líneas)
- ¿Qué hace esta amenaza?
- ¿A qué tipo de organización ataca típicamente?
- ¿Hay reportes de actividad en Latinoamérica?

### 4.3 Detalle técnico (extraído de las fuentes)
- Descripción extendida (primeros 500 caracteres)
- Enlaces a referencias originales
- IoCs asociados (IPs, dominios, hashes, URLs)

### 4.4 Guía de acción (lo más valioso)

**Opción A - Verificación rápida (para el admin de seguridad):**
> Comandos concretos para saber si el entorno es vulnerable o está comprometido.

**Opción B - Escaneo/herramientas (para el threat hunter):**
> Herramientas específicas (nmap, nuclei, metasploit, custom scripts) con sintaxis de ejemplo.

**Opción C - Prueba manual (para el pentester):**
> Pasos narrativos para reproducir o validar la vulnerabilidad/ataque.

*La herramienta decidirá qué opciones aplicar según el tipo de amenaza (ej: un CVE tendrá más Opción A/B; un Pulse de campaña de phishing tendrá más Opción C).*

## 5. Restricciones Técnicas y de Entorno

- **Entorno de ejecución:** Google Colab (no requiere instalación local)
- **Lenguaje:** Python 3.9+
- **Dependencias principales:** `requests`, `python-dotenv` (opcional), `datetime`
- **Manejo de secretos:** API keys se ingresan como variables en el notebook o archivo `.env` en Colab
- **Sin almacenamiento persistente:** Cada ejecución es independiente (no requiere base de datos)

## 6. Criterios de Aceptación (DoD - Definition of Done)

- [ ] El script se ejecuta sin errores en una celda de Google Colab.
- [ ] Conecta exitosamente a OTX y obtiene Pulses de las últimas 24h.
- [ ] Filtra correctamente por palabras clave, severidad y tecnologías.
- [ ] Genera un archivo `.txt` con el formato descrito.
- [ ] El archivo se puede descargar desde Colab.
- [ ] El usuario puede modificar las listas de filtrado sin tocar el código (archivo de config externo o celdas dedicadas).

## 7. Roadmap de Desarrollo (por fases)

| Fase | Entregable | Estado |
|:---|:---|:---|
| **Fase 0** | Configuración del notebook en Colab con variables de entorno | Pendiente |
| **Fase 1** | Conexión a OTX + filtrado + reporte básico (solo sección ejecutiva) | Pendiente |
| **Fase 2** | Integración con NVD/CVE | Pendiente |
| **Fase 3** | Integración con VirusTotal (enriquecimiento) | Pendiente |
| **Fase 4** | Generación de guías de acción (Opción A, B, C según tipo) | Pendiente |
| **Fase 5** | Refinamientos y configuración externa de filtros | Pendiente |

---
*Documento generado el: [fecha actual]*
*Responsable de especificación: [tu nombre]*