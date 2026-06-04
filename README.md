 Especificación del Proyecto: Threat-Alert-Action (TAA)

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
- [ ] Roadmap de Desarrollo (por fases)

| Fase | Entregable | Estado |
|:---|:---|:---|
| **Fase 0** | Configuración del notebook en Colab con variables de entorno | Pendiente |
| **Fase 1** | Conexión a OTX + filtrado + reporte básico (solo sección ejecutiva) | Pendiente |
| **Fase 2** | Integración con NVD/CVE | Pendiente |
| **Fase 3** | Integración con VirusTotal (enriquecimiento) | Pendiente |
| **Fase 4** | Generación de guías de acción (Opción A, B, C según tipo) | Pendiente |
| **Fase 5** | Refinamientos y configuración externa de filtros | Pendiente |
