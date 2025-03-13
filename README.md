# LogIPCore

## Instalación

1. Clona el repositorio:
   ```
   git clone https://github.com/m31r0n/LogIPCore
   cd LogIPCore
   ```
2. Descarga la base de datos **GeoLite2-Country.mmdb** desde [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/) y colócala en el directorio adecuado (por ejemplo, en la carpeta `data/`).

3. Configura tus API keys y otros parámetros en el archivo `config/config.ini`.

4. Instala las dependencias requeridas:
   ```
   pip install -r requirements.txt
   ```

## Uso

Ejecuta la herramienta desde la raíz del proyecto:

```
python -m src.main
```

Al iniciar, se mostrará un menú interactivo con las siguientes opciones:

1. **Analizar archivo de IPs simples:**  
   - Procesa un archivo con IPs y consulta su reputación usando las APIs seleccionadas.
   - Genera un CSV con los siguientes campos:
     - `Analyzed_IP`: IP analizada.
     - `IP_Type`: Tipo de IP (External).
     - `IPAbuse`, `VirusTotal`, `CriminalIP`, `TOR`, `MaliciousScore`: Resultados de las APIs.
     - `Country`: País determinado por GeoLite2.

2. **Analizar archivos o carpeta de logs:**  
   - Extrae campos clave de los logs y genera un CSV estructurado.
   - Genera un **resumen global** con:
     - Total de IPs encontradas y únicas.
     - Total de IPs externas.
     - **Top 10 IPs más recurrentes**.

3. **Analizar logs Fortinet:**  
   - Procesa archivos de logs de Fortinet.
   - Extrae los campos relevantes.
   - Determina si la conexión fue exitosa o no.
   - Añade la columna `Connection_Status` en el CSV generado.

4. **Salir:**  
   - Cierra la herramienta.

---

## Módulos y Extensiones Futuras

- **Configuración Avanzada:**  
  - Soporte para múltiples perfiles de configuración (producción, pruebas).
  - Validación y actualización dinámica de parámetros.

- **Reportes y Visualización:**  
  - Generar reportes en **HTML** o **PDF**.
  - Incluir **gráficos** sobre actividad sospechosa, tendencias y distribución geográfica de IPs.

- **Correlación de Eventos:**  
  - Relacionar diferentes fuentes de logs.
  - Detectar patrones complejos o ataques coordinados.

- **Integración con SIEM y Alertas:**  
  - Enviar **notificaciones** por correo o Slack ante eventos sospechosos.
  - Integración con sistemas SIEM para análisis en tiempo real.

- **Almacenamiento de Datos:**  
  - Implementar una base de datos para búsquedas y análisis históricos.

---

## Contribuciones

Las contribuciones son bienvenidas. Si deseas colaborar, revisa las directrices en el archivo `CONTRIBUTING.md` (próximamente).

## Licencia

Este proyecto se distribuye bajo la licencia MIT. Consulta el archivo `LICENSE` para más detalles.
