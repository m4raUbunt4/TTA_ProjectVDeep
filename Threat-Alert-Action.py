#!/usr/bin/env python3
"""
Threat-Alert-Action (TAA) - CORREGIDO
Herramienta de inteligencia de amenazas para seguridad cloud
"""

import requests
import json
import os
import time
from datetime import datetime, timedelta

# ============================================================
# CONFIGURACIÓN
# ============================================================

OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

PALABRAS_CLAVE = [
    "zero day", "zeroday", "0day",
    "ransomware", "ransom",
    "sector bancario", "banca", "banco", "financiero",
    "latinamerica", "latinoamerica", "mexico", "méxico",
    "phishing", "ingenieria social"
]

TECNOLOGIAS = [
    "windows server", "windows", "active directory",
    "linux", "unix", "ubuntu", "centos", "redhat",
    "kubernetes", "k8s", "docker", "container",
    "aws", "amazon web services", "ec2", "s3",
    "gcp", "google cloud", "cloud",
    "vps", "vpn", "fortinet", "fortigate", "paloalto", "firewall"
]

CVSS_THRESHOLD = 7.6
MAX_PULSES_OTX = 100
MAX_CVES_NVD = 50

HEADERS = {
    "User-Agent": "Threat-Alert-Action/1.0 (Security Research Tool)"
}

# ============================================================
# VALIDACIÓN
# ============================================================

def validar_api_keys():
    """Valida que las API keys necesarias estén configuradas"""
    if not OTX_API_KEY:
        print("❌ ERROR: OTX_API_KEY no encontrada")
        print("   Ejecuta: export OTX_API_KEY='tu_clave'")
        return False
    
    vt_disponible = bool(VT_API_KEY)
    if not vt_disponible:
        print("⚠️  ADVERTENCIA: VT_API_KEY no encontrada")
    
    print(f"✅ OTX_API_KEY configurada")
    print(f"{'✅' if vt_disponible else '⚠️'} VT_API_KEY {'configurada' if vt_disponible else 'no configurada'}")
    return True

# ============================================================
# OTX
# ============================================================

def obtener_pulses_otx(horas=24):
    """Obtiene pulses de AlienVault OTX de las últimas X horas"""
    print(f"📡 Consultando OTX: pulses de últimas {horas} horas...")
    
    since_date = (datetime.now() - timedelta(hours=horas)).strftime("%Y-%m-%dT%H:%M:%S")
    
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "User-Agent": HEADERS["User-Agent"]
    }
    params = {"modified_since": since_date, "limit": MAX_PULSES_OTX}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()
        response.encoding = 'utf-8'
        
        data = response.json()
        pulses = data.get("results", [])
        print(f"   ✅ Obtenidos {len(pulses)} pulses")
        return pulses
        
    except requests.exceptions.JSONDecodeError as e:
        print(f"   ❌ Error parseando JSON de OTX: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Error de conexión OTX: {e}")
        return []
    except Exception as e:
        print(f"   ❌ Error OTX: {e}")
        return []

# ============================================================
# CVE
# ============================================================

def obtener_cves_recientes(dias=1):
    """
    Obtiene CVEs recientes desde la API pública de MITRE CVE
    Usa el CVE JSON 5.0 format (nuevo estándar)
    """
    print(f"📡 Consultando MITRE CVE: vulnerabilidades de últimos {dias} días...")
    
    # Calcular fecha límite
    fecha_limite = (datetime.now() - timedelta(days=dias)).strftime("%Y-%m-%d")
    
    # Endpoint público de MITRE CVE (no requiere API key)
    # Fuente: https://cve.circl.lu (servicio público de CIRCL)
    url = f"https://cve.circl.lu/api/last/{dias}"
    
    headers = {
        "User-Agent": "Threat-Alert-Action/1.0 (Security Research Tool)",
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        response.encoding = 'utf-8'
        
        data = response.json()
        
        # El API de CIRCL devuelve una lista de CVEs
        if isinstance(data, list):
            cves_raw = data
        else:
            cves_raw = data.get("results", [])
        
        if not cves_raw:
            print("   ℹ️ No se encontraron CVEs nuevos en los últimos días")
            return []
        
        # Filtrar por severidad (CVSS >= threshold)
        cves_filtradas = []
        for cve in cves_raw:
            # Buscar el CVSS score en diferentes lugares del JSON
            score = 0
            
            # Formato CVE JSON 5.0: los metrics están dentro de containers
            containers = cve.get("containers", {})
            
            # Buscar en cna (CVE Numbering Authority)
            cna = containers.get("cna", {})
            metrics_cna = cna.get("metrics", [])
            for metric in metrics_cna:
                cvss_v3 = metric.get("cvssV3_0") or metric.get("cvssV3_1")
                if cvss_v3 and isinstance(cvss_v3, dict):
                    score = float(cvss_v3.get("baseScore", 0))
                    if score > 0:
                        break
            
            # Si no encontró en cna, buscar en adp (Authorized Data Publishers)
            if score == 0:
                adp_list = containers.get("adp", [])
                for adp in adp_list:
                    metrics_adp = adp.get("metrics", [])
                    for metric in metrics_adp:
                        cvss_v3 = metric.get("cvssV3_0") or metric.get("cvssV3_1")
                        if cvss_v3 and isinstance(cvss_v3, dict):
                            score = float(cvss_v3.get("baseScore", 0))
                            if score > 0:
                                break
                    if score > 0:
                        break
            
            # Formato alternativo (algunos CVEs tienen estructura diferente)
            if score == 0:
                # Intentar con el campo impact (versiones antiguas)
                impact = cve.get("impact", {})
                if "baseMetricV3" in impact:
                    score = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore", 0)
            
            if score >= CVSS_THRESHOLD:
                # Extraer descripción
                descripcion = ""
                desc_list = cve.get("description", {}).get("description_data", [])
                if desc_list:
                    descripcion = desc_list[0].get("value", "")
                elif "descriptions" in cve:
                    desc_list = cve.get("descriptions", [])
                    if desc_list:
                        descripcion = desc_list[0].get("value", "")
                
                cves_filtradas.append({
                    "id": cve.get("id", "CVE-UNKNOWN"),
                    "descriptions": [{"value": descripcion}] if descripcion else [],
                    "metrics": {
                        "cvssMetricV3": [{
                            "cvssData": {"baseScore": score, "severity": "HIGH" if score >= 7.0 else "MEDIUM"}
                        }]
                    },
                    "publishedDate": cve.get("published", ""),
                    "lastModifiedDate": cve.get("modified", "")
                })
        
        print(f"   ✅ Obtenidos {len(cves_raw)} CVEs totales, {len(cves_filtradas)} con CVSS >= {CVSS_THRESHOLD}")
        return cves_filtradas
        
    except requests.exceptions.JSONDecodeError as e:
        print(f"   ❌ Error parseando JSON de MITRE CVE: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Error de conexión a MITRE CVE: {e}")
        return []
    except Exception as e:
        print(f"   ❌ Error inesperado MITRE CVE: {e}")
        return []

# ============================================================
# FILTRADO
# ============================================================

def filtrar_relevante(items, tipo="pulse"):
    """Filtra items por palabras clave y tecnologías"""
    if not items:
        return []
    
    relevantes = []
    for item in items:
        if tipo == "pulse":
            texto = json.dumps({
                "name": item.get("name", ""),
                "description": item.get("description", ""),
                "tags": item.get("tags", [])
            }).lower()
            id_item = item.get("id", "unknown")
            titulo = item.get("name", "Sin título")
        else:
            texto = json.dumps({
                "id": item.get("id", ""),
                "descriptions": item.get("descriptions", [])
            }).lower()
            id_item = item.get("id", "unknown")
            titulo = id_item
        
        keywords_match = [kw for kw in PALABRAS_CLAVE if kw.lower() in texto]
        tech_match = [tech for tech in TECNOLOGIAS if tech.lower() in texto]
        
        if keywords_match or tech_match:
            item_copy = item.copy() if isinstance(item, dict) else item
            item_copy["_relevance"] = {
                "keywords": keywords_match,
                "technologies": tech_match,
                "tipo": tipo
            }
            item_copy["_titulo"] = titulo
            relevantes.append(item_copy)
    
    print(f"   🔍 Filtrados: {len(relevantes)} de {len(items)} items")
    return relevantes

# ============================================================
# GUÍA DE ACCIÓN
# ============================================================

def generar_guia_accion(amenaza):
    """Genera guía de acción según el tipo de amenaza"""
    tipo = amenaza.get("_relevance", {}).get("tipo", "pulse")
    keywords = amenaza.get("_relevance", {}).get("keywords", [])
    
    guia = {"A": "", "B": "", "C": ""}
    
    es_phishing = any(k in ["phishing", "ingenieria social"] for k in keywords)
    
    # Opción A
    comandos = [
        "# Verificar procesos sospechosos",
        "ps aux | grep -E 'nc|reverse|shell'",
        "",
        "# Verificar puertos abiertos",
        "ss -tulpn | grep LISTEN"
    ]
    if es_phishing:
        comandos.extend(["", "# Revisar correos sospechosos", "grep -i 'from:\\|subject:' /var/log/mail.log | tail -20"])
    guia["A"] = "\n".join(comandos)
    
    # Opción B
    herramientas = [
        "nmap --script vuln -sV <target_ip>",
        "nuclei -u https://<target> -t cves/"
    ]
    guia["B"] = "\n".join(herramientas)
    
    # Opción C
    pasos = [
        "1. Revisar logs del sistema en busca de actividad anómala",
        "2. Verificar integridad de binarios críticos",
        "3. Correlacionar con IoCs públicos"
    ]
    guia["C"] = "\n".join(pasos)
    
    return guia

# ============================================================
# REPORTE
# ============================================================

def generar_reporte(amenazas, fecha_str):
    """Genera archivo de reporte en texto plano"""
    nombre_archivo = f"reporte_{fecha_str}.txt"
    
    with open(nombre_archivo, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"THREAT-ALERT-ACTION (TAA) - Reporte\n")
        f.write(f"Fecha: {fecha_str}\n")
        f.write(f"Total amenazas relevantes: {len(amenazas)}\n")
        f.write("=" * 70 + "\n\n")
        
        if not amenazas:
            f.write("✅ No se encontraron amenazas relevantes.\n")
            return nombre_archivo
        
        for i, amenaza in enumerate(amenazas, 1):
            relev = amenaza.get("_relevance", {})
            tipo = relev.get("tipo", "unknown")
            titulo = amenaza.get("_titulo", "Sin título")
            keywords = ", ".join(relev.get("keywords", []))
            
            f.write(f"\n{'─' * 70}\n")
            f.write(f"AMENAZA #{i}\n")
            f.write(f"{'─' * 70}\n")
            f.write(f"\n📌 RESUMEN EJECUTIVO\n")
            f.write(f"   ID: {titulo}\n")
            f.write(f"   Tipo: {tipo.upper()}\n")
            f.write(f"   Palabras clave: {keywords}\n")
            
            # Detalle técnico
            f.write(f"\n🔧 DETALLE TÉCNICO\n")
            if tipo == "pulse":
                f.write(f"   Nombre: {amenaza.get('name', 'N/A')}\n")
                f.write(f"   Descripción: {amenaza.get('description', 'N/A')[:300]}\n")
            else:
                f.write(f"   ID CVE: {amenaza.get('id', 'N/A')}\n")
                desc = amenaza.get('descriptions', [{}])[0].get('value', 'N/A')
                f.write(f"   Descripción: {desc[:300]}\n")
            
            # Guía de acción
            guia = generar_guia_accion(amenaza)
            f.write(f"\n🛠️  GUÍA DE ACCIÓN\n")
            f.write(f"\n   OPCIÓN A - Verificación rápida:\n")
            for linea in guia["A"].split("\n"):
                f.write(f"      {linea}\n")
            f.write(f"\n   OPCIÓN B - Herramientas:\n")
            for linea in guia["B"].split("\n"):
                f.write(f"      {linea}\n")
            f.write(f"\n   OPCIÓN C - Pasos manuales:\n")
            for linea in guia["C"].split("\n"):
                f.write(f"      {linea}\n")
        
        f.write(f"\n{'=' * 70}\nFin del reporte\n")
    
    return nombre_archivo

# ============================================================
# MAIN
# ============================================================

def main():
    print("\n" + "=" * 60)
    print("THREAT-ALERT-ACTION (TAA) - Iniciando")
    print("=" * 60 + "\n")
    
    if not validar_api_keys():
        return
    
    pulses = obtener_pulses_otx(horas=24)
    cves = obtener_cves_recientes(dias=1)
    
    print("\n🔍 Filtrando...")
    pulses_rel = filtrar_relevante(pulses, tipo="pulse")
    cves_rel = filtrar_relevante(cves, tipo="cve")
    
    todas = pulses_rel + cves_rel
    fecha = datetime.now().strftime("%Y-%m-%d")
    reporte = generar_reporte(todas, fecha)
    
    print("\n" + "=" * 60)
    print("RESUMEN")
    print("=" * 60)
    print(f"📊 OTX: {len(pulses)} pulses, {len(pulses_rel)} relevantes")
    print(f"📊 NVD: {len(cves)} CVEs, {len(cves_rel)} relevantes")
    print(f"🎯 Total amenazas: {len(todas)}")
    print(f"📄 Reporte: {reporte}")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
