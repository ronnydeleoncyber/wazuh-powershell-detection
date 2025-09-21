# 🔎 wazuh-powershell-detection

**Detección de ejecución maliciosa en PowerShell con Wazuh.**  
Reglas, configuraciones y prueba práctica mapeada a **MITRE ATT&CK (T1059.001)**.

Este repositorio contiene el **código, configuraciones y reglas personalizadas** utilizadas para detectar la ejecución de comandos maliciosos en PowerShell mediante **Wazuh**.

🎥 **Video demostrativo en YouTube**  
👉 [Ver el paso a paso en acción](https://www.youtube.com/watch?v=av4nRYwxxiQ)

---

## 📂 Contenido
- `ossec.conf` (fragmento) — configuración mínima para capturar eventos de PowerShell en el agente Windows
- `local_rules.xml` — reglas personalizadas para Wazuh (server/manager)
- `ps_test_scripts/` — scripts PowerShell inofensivos para pruebas
- `README.md` — esta documentación

---

## ⚙️ Requisitos / Consideraciones
- **Laboratorio**: Windows 11 (endpoint) + Wazuh Agent instalado + Wazuh Manager (Ubuntu)
- Se recomienda usar un **entorno de pruebas** (no ejecutar malware real en producción)
- Habilitar **ScriptBlockLogging** y **ModuleLogging** en Windows para obtener visibilidad completa de PowerShell
- **Opcional pero recomendado**: instalar Sysmon para mejores datos forenses (ProcessCreate con IncludeCmdLine)

---

## 🔧 Paso 1 — Habilitar el registro de PowerShell (Windows)

Abre PowerShell como **Administrador** y ejecuta:

```powershell
function Enable-PSLogging {
    $scriptBlockPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $moduleLoggingPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'

    if (-not (Test-Path $scriptBlockPath)) { New-Item $scriptBlockPath -Force }
    Set-ItemProperty -Path $scriptBlockPath -Name EnableScriptBlockLogging -Value 1

    if (-not (Test-Path $moduleLoggingPath)) { New-Item $moduleLoggingPath -Force }
    Set-ItemProperty -Path $moduleLoggingPath -Name EnableModuleLogging -Value 1

    $moduleNames = @('*')
    New-ItemProperty -Path $moduleLoggingPath -Name ModuleNames -PropertyType MultiString -Value $moduleNames -Force

    Write-Output "Script Block Logging and Module Logging have been enabled."
}

Enable-PSLogging
```

### ¿Qué hace?
Activa **Script Block Logging** y **Module Logging**, lo que permite registrar el contenido de scripts y módulos ejecutados por PowerShell. Esto es crucial para detección y análisis forense.

---

## 🖥️ Paso 2 — Configuración del agente Wazuh (Windows)

Edita (como Administrador) el archivo del agente Wazuh:

```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Añade el bloque para capturar el canal de eventos de PowerShell:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Luego reinicia el servicio del agente:

```powershell
Restart-Service -Name wazuh
```

### 📋 Notas importantes:
- Asegúrate de que el agente tenga permisos para leer el canal de eventos (ejecutar como Local System suele ser suficiente)
- Revisa que la comunicación TLS/puerto hacia el manager esté habilitada si lo usas

---

## 🛡️ Paso 3 — Reglas de detección (Wazuh Manager / Ubuntu)

En el servidor Wazuh, edita o crea el archivo de reglas locales:

```
/var/ossec/etc/rules/local_rules.xml
```

Agrega las siguientes reglas (ejemplo):

```xml
<group name="windows,powershell,">

  <rule id="100201" level="8">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.payload" type="pcre2">(?i)CommandInvocation</field>
    <field name="win.system.message" type="pcre2">(?i)EncodedCommand|FromBase64String|EncodedArguments|-e\b|-enco\b|-en\b</field>
    <description>Encoded command executed via PowerShell.</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1562.001</id>
    </mitre>
  </rule>
  
  <rule id="100202" level="4">
    <if_sid>60009</if_sid>
    <field name="win.system.message" type="pcre2">(?i)blocked by your antivirus software</field>
    <description>Windows Security blocked malicious command executed via PowerShell.</description>
    <mitre>
      <id>T1059.001</id>  
    </mitre>
  </rule>

  <rule id="100203" level="10">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.payload" type="pcre2">(?i)CommandInvocation</field>    
    <field name="win.system.message" type="pcre2">(?i)Add-Persistence|Find-AVSignature|Get-GPPAutologon|Get-GPPPassword|Get-HttpStatus|Get-Keystrokes|Get-SecurityPackages|Get-TimedScreenshot|Get-VaultCredential|Get-VolumeShadowCopy|Install-SSP|Invoke-CredentialInjection|Invoke-DllInjection|Invoke-Mimikatz|Invoke-NinjaCopy|Invoke-Portscan|Invoke-ReflectivePEInjection|Invoke-ReverseDnsLookup|Invoke-Shellcode|Invoke-TokenManipulation|Invoke-WmiCommand|Mount-VolumeShadowCopy|New-ElevatedPersistenceOption|New-UserPersistenceOption|New-VolumeShadowCopy|Out-CompressedDll|Out-EncodedCommand|Out-EncryptedScript|Out-Minidump|PowerUp|PowerView|Remove-Comments|Remove-VolumeShadowCopy|Set-CriticalProcess|Set-MasterBootRecord</field>
    <description>Risky CMDLet executed. Possible malicious activity detected.</description>
    <mitre>
      <id>T1059.001</id>  
    </mitre>
  </rule>

  <rule id="100204" level="8">
    <if_sid>91802</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)mshta.*GetObject|mshta.*new ActiveXObject</field>
    <description>Mshta used to download a file. Possible malicious activity detected.</description>
    <mitre>
      <id>T1059.001</id>  
    </mitre>
  </rule>

  <rule id="100205" level="5">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.contextInfo" type="pcre2">(?i)ExecutionPolicy bypass|exec bypass</field>
    <description>PowerShell execution policy set to bypass.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <rule id="100206" level="5">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.contextInfo" type="pcre2">(?i)Invoke-WebRequest|IWR.*-url|IWR.*-InFile</field>
    <description>Invoke Webrequest executed, possible download cradle detected.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>
```

### ⚠️ Notas importantes:
- `if_sid` debe coincidir con la SID que produce Wazuh para eventos de PowerShell en tu instalación. Ajusta si es necesario
- Prueba tus reglas con `ossec-logtest` usando eventos reales o copiados para validar decodificadores y coincidencias
- Evita regex excesivamente amplios para reducir falsos positivos

---

## 🧪 Paso 4 — Prueba de detección (Windows 11)

En Windows 11, ejecuta un comando de prueba (inofensivo) para simular ejecución codificada:

```powershell
powershell.exe -EncodedCommand SQBFAFgAUwBFAFMAVwBTAE0ALgBTAFQALgAtAFcATABTAEMARQBSAA==
```

### 📊 Resultado esperado:
- Ese `EncodedCommand` es solo un ejemplo inofensivo que provoca la generación de los eventos que las reglas detectarán
- En el **Wazuh Dashboard** o en los logs del manager deberías ver una alerta generada por la regla con `id=100201` (nivel 8) si todo está configurado correctamente

---

## 🎯 Mapeo MITRE ATT&CK

- **T1059.001** – PowerShell (Command and Scripting Interpreter: PowerShell)
- **T1562.001** – Impair Defenses (si aplica a manipulación de defensas)

---

## 💡 Buenas prácticas y recomendaciones

- ✅ Realiza pruebas en un **entorno controlado**
- ✅ Versiona `local_rules.xml` con **Git** para mantener historial de cambios
- ✅ **Documenta cada regla** (motivo, pruebas, falsos positivos conocidos)
- ✅ Habilita **Sysmon** para mejorar visibilidad (ProcessCreate con IncludeCmdLine)
- ⚠️ Monitorea el uso de **disco/CPU** en endpoints cuando habilitas ScriptBlockLogging (puede aumentar uso de recursos)
- ✅ Considera **listas de exclusión** (whitelists) para reducir ruido

---

## ⚠️ Advertencias

- Los scripts incluidos en este repositorio son para **laboratorio y propósitos educativos**
- **No ejecutes código desconocido en producción**
- No se recomienda activar correcciones automáticas (**active-response**) en producción sin pruebas exhaustivas por riesgo de interrupciones
