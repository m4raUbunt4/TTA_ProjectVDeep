# Lista de Tareas: Threat-Alert-Action (TAA)

## Fase 0: Preparación del Entorno

- [ ] 0.1 Verificar Python instalado: `python3 --version` (debe ser 3.8+)
- [ ] 0.2 Instalar requests: `pip3 install requests`
- [ ] 0.3 Crear carpeta del proyecto: `mkdir ~/Documentos/Threat-Alert-Action`
- [ ] 0.4 Dentro de la carpeta, crear archivo `threat_alert_action.py` vacío
- [ ] 0.5 Probar que las API keys funcionan (prueba manual con curl o script básico)

## Fase 1: Estructura Base del Script

- [ ] 1.1 Agregar shebang al inicio: `#!/usr/bin/env python3`
- [ ] 1.2 Agregar imports: `import requests, json, os, time`
- [ ] 1.3 Agregar imports de fechas: `from datetime import datetime, timedelta`
- [ ] 1.4 Crear sección CONFIGURACIÓN con variables:
  - [ ] 1.4.1 `OTX_API_KEY = os.getenv("OTX_API_KEY")`
  - [ ] 1.4.2 `VT_API_KEY = os.getenv("VT_API_KEY")`
  - [ ] 1.4.3 `PALABRAS_CLAVE = ["zero day", "ransomware", ...]`
  - [ ] 1.4.4 `TECNOLOGIAS = ["windows server", "linux", ...]`
- [ ] 1.5 Crear función `main()` vacía y bloque `if __name__ == "__main__": main()`

## Fase 2: Validación de API Keys

- [ ] 2.1 Escribir validación de OTX_API_KEY al inicio de `main()`
  - [ ] 2.1.1 Si es None: imprimir error y `exit(1)`
- [ ] 2.2 Escribir validación de VT_API_KEY
  - [ ] 2.2.1 Si es None: imprimir advertencia, crear flag `vt_disponible = False`
  - [ ] 2.2.2 Si tiene valor: `vt_disponible = True`

## Fase 3: Función para OTX (obtener_pulses_otx)

- [ ] 3.1 Definir `obtener_pulses_otx(horas=24)`:
  - [ ] 3.1.1 Calcular fecha `modified_since` (datetime.now - horas)
  - [ ] 3.1.2 Construir URL: `https://otx.alienvault.com/api/v1/pulses/subscribed`
  - [ ] 3.1.3 Agregar headers: `{"X-OTX-API-KEY": OTX_API_KEY}`
  - [ ] 3.1.4 Agregar parámetros: `{"modified_since": fecha_iso, "limit": 100}`
- [ ] 3.2 Ejecutar `requests.get()` dentro de try/except
  - [ ] 3.2.1 Si error de red: imprimir error, retornar lista vacía
  - [ ] 3.2.2 Si status != 200: imprimir error, retornar lista vacía
- [ ] 3.3 Parsear JSON y retornar `results` (lista de pulses)
- [ ] 3.4 Agregar sleep(1) para respetar rate limit

## Fase 4: Función para NVD/CVE (obtener_cves_recientes)

- [ ] 4.1 Definir `obtener_cves_recientes(dias=1)`:
  - [ ] 4.1.1 Calcular `pubStartDate` (hoy - dias)
  - [ ] 4.1.2 Construir URL base: `https://services.nvd.nist.gov/rest/json/cves/2.0`
  - [ ] 4.1.3 Parámetros: `pubStartDate`, `pubEndDate` (hoy), `cvssV3Severity=CRITICAL,HIGH`
- [ ] 4.2 Ejecutar `requests.get()` con timeout 10s
- [ ] 4.3 Parsear respuesta y extraer lista `vulnerabilities`
- [ ] 4.4 Retornar solo CVEs con cvssV3Score >= 7.6
- [ ] 4.5 Agregar sleep(6) entre llamadas (respetar 5 requests/30 seg)

## Fase 5: Función de Filtrado (filtrar_relevante)

- [ ] 5.1 Definir `filtrar_relevante(items, tipo)` donde tipo es "pulse" o "cve"
- [ ] 5.2 Para cada item:
  - [ ] 5.2.1 Convertir todo el texto a minúsculas
  - [ ] 5.2.2 Verificar si alguna PALABRA_CLAVE está presente
  - [ ] 5.2.3 Si es CVE, verificar si CVSS >= 7.6 (ya viene filtrado)
  - [ ] 5.2.4 Verificar si alguna TECNOLOGIA está presente
- [ ] 5.3 Si cumple algún criterio, agregar a lista `relevantes`
- [ ] 5.4 Retornar lista de items relevantes con campo adicional `keywords_match`

## Fase 6: Función para VirusTotal (enriquecer_con_vt)

- [ ] 6.1 Definir `enriquecer_con_vt(ioc, tipo)` donde tipo es "domain", "ip", o "hash"
- [ ] 6.2 Si `vt_disponible` es False, retornar None
- [ ] 6.3 Construir URL según tipo: 
  - [ ] 6.3.1 Dominio: `https://www.virustotal.com/api/v3/domains/{ioc}`
  - [ ] 6.3.2 IP: `https://www.virustotal.com/api/v3/ip_addresses/{ioc}`
  - [ ] 6.3.3 Hash: `https://www.virustotal.com/api/v3/files/{ioc}`
- [ ] 6.4 Headers: `{"x-apikey": VT_API_KEY}`
- [ ] 6.5 Ejecutar GET con try/except
- [ ] 6.6 Si éxito, retornar resumen (número de detecciones, análisis)
- [ ] 6.7 Agregar sleep(15) entre consultas (respetar 4 por minuto)

## Fase 7: Función para Generar Guía de Acción (generar_guia_accion)

- [ ] 7.1 Definir `generar_guia_accion(amenaza, tipo)`:
  - [ ] 7.1.1 Si tipo es "cve": priorizar Opción A (comandos) y Opción B (herramientas)
  - [ ] 7.1.2 Si tipo es "pulse" con palabras clave de phishing/ingeniería social: priorizar Opción C (pasos manuales)
  - [ ] 7.1.3 Caso contrario: incluir las tres opciones genéricas
- [ ] 7.2 Para Opción A (comandos):
  - [ ] 7.2.1 Si es CVE: sugerir `grep`, `find`, comandos de versión específicos
  - [ ] 7.2.2 Si es IoC de red: sugerir `ping`, `nslookup`, `curl`
  - [ ] 7.2.3 Si es hash: sugerir `find` + `sha256sum`
- [ ] 7.3 Para Opción B (herramientas):
  - [ ] 7.3.1 Si es CVE web: sugerir `nmap --script vuln`, `nuclei`
  - [ ] 7.3.2 Si es CVE de red: sugerir `metasploit`, `searchsploit`
- [ ] 7.4 Para Opción C (pasos manuales):
  - [ ] 7.4.1 Describir pasos narrativos genéricos según el tipo de amenaza
- [ ] 7.5 Retornar diccionario con las tres opciones

## Fase 8: Función para Generar Reporte (generar_reporte)

- [ ] 8.1 Definir `generar_reporte(amenazas, fecha)`:
  - [ ] 8.1.1 Crear nombre de archivo: `f"reporte_{fecha}.txt"`
- [ ] 8.2 Escribir cabecera del reporte (fecha, total de amenazas)
- [ ] 8.3 Para cada amenaza:
  - [ ] 8.3.1 Escribir sección "Ejecutivo" (resumen corto, impacto, keywords)
  - [ ] 8.3.2 Escribir sección "Técnico" (ID, score, descripción, enlaces, IoCs)
  - [ ] 8.3.3 Escribir sección "Acción" (Opción A, B, C según generado)
  - [ ] 8.3.4 Escribir separador "---"
- [ ] 8.4 Guardar archivo en disco
- [ ] 8.5 Retornar nombre del archivo

## Fase 9: Integración en main() - Orquestación

- [ ] 9.1 En `main()`, llamar a `obtener_pulses_otx()` y guardar resultado
- [ ] 9.2 Llamar a `obtener_cves_recientes()` y guardar resultado
- [ ] 9.3 Aplicar `filtrar_relevante()` a pulses y a cves
- [ ] 9.4 Para cada pulse relevante, extraer IoCs y (opcional) llamar a `enriquecer_con_vt()`
- [ ] 9.5 Para cada amenaza relevante, llamar a `generar_guia_accion()`
- [ ] 9.6 Unir todas las amenazas filtradas en una sola lista
- [ ] 9.7 Llamar a `generar_reporte()` con la lista y fecha actual
- [ ] 9.8 Imprimir resumen en pantalla (cantidades y nombre del archivo)

## Fase 10: Pruebas y Refinamiento

- [ ] 10.1 Ejecutar script con API keys válidas
- [ ] 10.2 Verificar que se genera archivo `.txt`
- [ ] 10.3 Revisar manualmente el contenido del reporte
- [ ] 10.4 Probar con diferentes fechas cambiando parámetros
- [ ] 10.5 Verificar manejo de errores (desconectar WiFi, API key inválida)
- [ ] 10.6 Ajustar palabras clave según resultados obtenidos
- [ ] 10.7 (Opcional) Agregar la opción de leer keywords desde archivo externo

---

## Resumen de Dependencia entre Tareas
