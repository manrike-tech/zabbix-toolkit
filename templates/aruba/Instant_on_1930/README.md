# Aruba Instant On 1930 - Zabbix Template

Plantilla de Zabbix para monitorear switches Aruba Instant On 1930 mediante SNMP.

## Descripción

Esta plantilla define los elementos básicos y avanzados para monitorear:

- Estado y disponibilidad ICMP
- Disponibilidad del agente SNMP
- Información del sistema (CPU, firmware, versión, serial, ubicación, nombre)
- Interfaces de red con tráfico, errores y discards
- Descubrimiento automático de memoria, ventiladores, fuentes de poder, temperatura y estado de pares Ethernet
- Monitorización PoE global y por puerto
- Vecinos LLDP, estado STP, VLAN/PVID, LACP y storm-control
- Traps SNMP separados por categorías operativas
- Gráficas y disparadores relacionados con rendimiento y salud

## Archivo

- `Instant_on_1930.xml`: exportación XML de plantilla Zabbix para Zabbix 6.0.

## Secciones principales

### Items

Contiene métricas de tipo:

- `SIMPLE` para ping ICMP
- `SNMP_AGENT` para consultas SNMP
- `INTERNAL` para disponibilidad interna de Zabbix
- `SNMP_TRAP` para recepción general de traps
- `CALCULATED` para cálculos derivados

Áreas añadidas desde los MIBs del firmware 3.4.0.6:

- `POWER-ETHERNET-MIB` y `HPE-POE-MIB` para consumo PoE, estado PSE y errores por puerto
- `LLDP-MIB` para vecinos conectados
- `BRIDGE-MIB` y `Q-BRIDGE-MIB` para STP, VLAN y PVID
- `HPE-TRUNK-MIB` para estado LACP
- `HPE-STORMCTRL-MIB` para rate-limit/storm-control
- `HPE-TRAPS-MIB` como referencia para clasificar traps

### Triggers

Los triggers definen alertas basadas en expresiones Zabbix que usan:

- funciones como `min()`, `max()`, `avg()`, `last()`, `count()`, `change()`
- macros de plantilla como `{$ICMP_LOSS_WARN}`, `{$CPU.UTIL.CRIT}`, `{$TEMP_WARN}`
- dependencias entre triggers para evitar alertas redundantes
- modo de recuperación y expresiones de recuperación

### Descubrimiento automático (LLD)

Incluye reglas para descubrir automáticamente:

- entidades físicas (`Entity Discovery`)
- ventiladores (`FAN Discovery`)
- memoria (`Memory Discovery`)
- interfaces de red (`Network interfaces discovery`)
- estados de duplex (`EtherLike-MIB Discovery`)
- fuentes de poder (`PSU Discovery`)
- sensores de temperatura y estado (`Temperature Discovery`, `Temp Status Discovery`)
- puertos PoE (`PoE ports discovery`)
- vecinos LLDP (`LLDP neighbors discovery`)
- puertos STP (`STP ports discovery`)
- VLANs estáticas (`VLAN discovery`)
- puertos LACP (`LACP ports discovery`)
- entradas de storm-control (`Storm-control discovery`)

Los prototipos usan macros de bajo nivel como `{#IFNAME}`, `{#IFALIAS}`, `{#SNMPINDEX}` y `{#ENT_DESCR}`.

### Preprocesamiento

Algunos items usan pasos de preprocesamiento como:

- `DISCARD_UNCHANGED_HEARTBEAT`
- `MULTIPLIER`
- `CHANGE_PER_SECOND`
- `JAVASCRIPT`

Estos pasos ajustan y estabilizan valores antes de almacenarlos en Zabbix.

### Gráficas y Dashboards

La plantilla incluye prototipos de gráficos para:

- uso de memoria
- tráfico de interfaces de red
- uso de CPU y métricas relevantes

También incluye un dashboard básico llamado "Network interfaces" que muestra gráficos de tráfico por interfaz.

### Valuemaps

Convierte valores numéricos SNMP en etiquetas legibles, por ejemplo:

- `IF-MIB::ifOperStatus` → `up`, `down`, `dormant`, `notPresent`
- `EtherLike-MIB::dot3StatsDuplexStatus` → `halfDuplex`, `fullDuplex`
- `HP-ICF-CHASSIS::hpicfSensorStatus` → `bad`, `warning`, `good`
- `PETH-MIB::pethPsePortDetectionStatus` → `deliveringPower`, `fault`, `otherFault`
- `BRIDGE-MIB::dot1dStpPortState` → `blocking`, `learning`, `forwarding`
- `HPE-TRUNK-MIB::lacpRxState` y `HPE-TRUNK-MIB::lacpMuxState`
- `HPE-STORMCTRL-MIB::trafficType`, `rateUnit` y `action`

### Macros

Macros de plantilla clave definidas aquí:

- `{$CPU.UTIL.CRIT}`
- `{$FAN_CRIT_STATUS:"bad"}`
- `{$IF.UTIL.MAX}`
- `{$MEMORY.UTIL.MAX}`
- `{$NET.IF.IFNAME.NOT_MATCHES}`
- `{$SNMP.TIMEOUT}`
- `{$TEMP_WARN}`
- `{$POE.POWER.UTIL.WARN}`
- `{$POE.PORT.DETECT.MATCHES}`
- `{$LLDP.NEIGHBOR.CHANGE}`
- `{$STP.TOPOLOGY.CHANGE.WARN}`
- `{$LACP.MONITOR}`
- `{$STORMCTRL.MONITOR}`

Estas macros permiten ajustar umbrales y filtros sin modificar directamente el XML.

## Importación en Zabbix

1. Abre la interfaz web de Zabbix.
2. Ve a `Configuration` → `Templates`.
3. Haz clic en `Import`.
4. Selecciona el archivo `Instant_on_1930.xml`.
5. Marca las opciones necesarias para importar items, triggers, discovery, graphs y macros.

## Recomendaciones

- Ajusta las macros de umbral según el ambiente y el tipo de tráfico.
- Revisa los filtros de descubrimiento para excluir interfaces no deseadas.
- Verifica que el host usa SNMPv2/3 según la configuración de tu entorno.
- Activa `{$LLDP.NEIGHBOR.CHANGE}` solo en puertos donde esperes vecinos estables.
- Mantén `{$STORMCTRL.MONITOR}=0` hasta comprobar que los contadores de storm-control están soportados por tu modelo y firmware.
- Revisa los OID PoE contra un switch real: algunos modelos no PoE o firmwares parciales pueden no exponer todas las tablas.

## Mantenimiento

El script `scripts/enrich_aruba_1930_template.py` reconstruye los bloques añadidos de forma idempotente sobre la exportación XML. Es útil si reexportas la plantilla desde Zabbix y quieres volver a aplicar las mejoras basadas en los MIBs incorporados.

## Uso

Esta plantilla es adecuada para monitorizar un switch Aruba Instant On 1930 y sus componentes principales con Zabbix.

Para una implementación completa, importa la plantilla y asóciala a un host con SNMP configurado.
