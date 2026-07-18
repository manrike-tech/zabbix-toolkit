#!/usr/bin/env python3
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path


TEMPLATE = "Aruba 1930 Switch SNMP"
XML_PATH = Path("templates/aruba/Instant_on_1930/Instant_on_1930.xml")


def uid(name):
    return hashlib.md5(f"aruba-1930:{name}".encode()).hexdigest()


def e(tag, text=None, children=None):
    node = ET.Element(tag)
    if text is not None:
        node.text = str(text)
    for child in children or []:
        node.append(child)
    return node


def tag(name, value):
    return e("tag", children=[e("tag", name), e("value", value)])


def tags(*pairs):
    return e("tags", children=[tag(k, v) for k, v in pairs])


def valuemap_ref(name):
    return e("valuemap", children=[e("name", name)])


def preprocessing(step_type, params):
    return e("preprocessing", children=[
        e("step", children=[
            e("type", step_type),
            e("parameters", children=[e("parameter", p) for p in params]),
        ])
    ])


def trigger(name, expression, priority="WARNING", opdata=None, description=None, deps=None, manual_close=False, scope=None):
    children = [
        e("uuid", uid(f"trigger:{name}")),
        e("expression", expression),
        e("name", name),
    ]
    if opdata:
        children.append(e("opdata", opdata))
    children.append(e("priority", priority))
    if description:
        children.append(e("description", description))
    if manual_close:
        children.append(e("manual_close", "YES"))
    if deps:
        children.append(e("dependencies", children=[
            e("dependency", children=[e("name", d[0]), e("expression", d[1])] + ([e("recovery_expression", d[2])] if len(d) > 2 else []))
            for d in deps
        ]))
    if scope:
        children.append(tags(("scope", scope)))
    return e("trigger", children=children)


def item(name, key, snmp_oid=None, item_type="SNMP_AGENT", delay=None, history=None, trends=None,
         value_type=None, units=None, description=None, valuemap=None, tags_pairs=None,
         preprocessing_steps=None, triggers=None, params=None):
    children = [e("uuid", uid(f"item:{key}")), e("name", name), e("type", item_type)]
    if snmp_oid:
        children.append(e("snmp_oid", snmp_oid))
    children.append(e("key", key))
    if delay:
        children.append(e("delay", delay))
    if history:
        children.append(e("history", history))
    if trends:
        children.append(e("trends", trends))
    if value_type:
        children.append(e("value_type", value_type))
    if units:
        children.append(e("units", units))
    if params:
        children.append(e("params", params))
    if description:
        children.append(e("description", description))
    if valuemap:
        children.append(valuemap_ref(valuemap))
    if preprocessing_steps:
        children.append(e("preprocessing", children=[
            e("step", children=[e("type", t), e("parameters", children=[e("parameter", p) for p in ps])])
            for t, ps in preprocessing_steps
        ]))
    if tags_pairs:
        children.append(tags(*tags_pairs))
    if triggers:
        children.append(e("triggers", children=triggers))
    return e("item", children=children)


def proto(name, key, snmp_oid=None, item_type="SNMP_AGENT", delay=None, history=None, trends=None,
          value_type=None, units=None, description=None, valuemap=None, tags_pairs=None,
          preprocessing_steps=None, trigger_prototypes=None, params=None):
    node = item(name, key, snmp_oid, item_type, delay, history, trends, value_type, units,
                description, valuemap, tags_pairs, preprocessing_steps, None, params)
    node.tag = "item_prototype"
    node.find("uuid").text = uid(f"proto:{key}")
    if trigger_prototypes:
        tp = e("trigger_prototypes")
        for tr in trigger_prototypes:
            tr.tag = "trigger_prototype"
            tr.find("uuid").text = uid(f"trigger-proto:{tr.findtext('name')}")
            tp.append(tr)
        node.append(tp)
    return node


def lld_macro(macro, value):
    return e("lld_macro_path", children=[e("lld_macro", macro), e("path", value)])


def rule(name, key, snmp_oid, description, item_prototypes=None, graph_prototypes=None,
         filter_conditions=None, lld_macro_paths=None):
    children = [
        e("uuid", uid(f"lld:{key}")),
        e("name", name),
        e("type", "SNMP_AGENT"),
        e("snmp_oid", snmp_oid),
        e("key", key),
        e("delay", "1h"),
    ]
    if filter_conditions:
        children.append(e("filter", children=[
            e("evaltype", "AND"),
            e("conditions", children=[
                e("condition", children=[
                    e("macro", c[0]),
                    e("value", c[1]),
                    *([e("operator", c[2])] if len(c) > 2 else []),
                    e("formulaid", chr(65 + i)),
                ]) for i, c in enumerate(filter_conditions)
            ]),
        ]))
    if lld_macro_paths:
        children.append(e("lld_macro_paths", children=[lld_macro(k, v) for k, v in lld_macro_paths]))
    children.append(e("description", description))
    if item_prototypes:
        children.append(e("item_prototypes", children=item_prototypes))
    if graph_prototypes:
        children.append(e("graph_prototypes", children=graph_prototypes))
    return e("discovery_rule", children=children)


def graph_proto(name, items):
    colors = ["199C0D", "2774A4", "F63100", "F7941D", "6C59DC", "FC6EA3"]
    return e("graph_prototype", children=[
        e("uuid", uid(f"graph-proto:{name}")),
        e("name", name),
        e("graph_items", children=[
            e("graph_item", children=[
                e("color", colors[i % len(colors)]),
                e("item", children=[e("host", TEMPLATE), e("key", key)]),
            ]) for i, key in enumerate(items)
        ]),
    ])


def valuemap(name, mappings):
    return e("valuemap", children=[
        e("uuid", uid(f"valuemap:{name}")),
        e("name", name),
        e("mappings", children=[e("mapping", children=[e("value", k), e("newvalue", v)]) for k, v in mappings]),
    ])


def add_if_missing(parent, child, key_tag, key_text):
    for existing in parent.findall(child.tag):
        if existing.findtext(key_tag) == key_text:
            return False
    parent.append(child)
    return True


def dedupe(parent, child_tag, key_tag):
    seen = set()
    for child in list(parent.findall(child_tag)):
        key = child.findtext(key_tag)
        if key in seen:
            parent.remove(child)
        else:
            seen.add(key)


def main():
    tree = ET.parse(XML_PATH)
    root = tree.getroot()
    root.find("version").text = "6.0"
    root.find("date").text = "2026-07-18T00:00:00Z"
    tmpl = root.find("./templates/template")
    items = tmpl.find("items")
    discoveries = tmpl.find("discovery_rules")
    macros = tmpl.find("macros")
    valuemaps = tmpl.find("valuemaps")

    new_maps = [
        valuemap("PETH-MIB::pethMainPseOperStatus", [("1", "on"), ("2", "off"), ("3", "faulty")]),
        valuemap("PETH-MIB::pethPsePortDetectionStatus", [("1", "disabled"), ("2", "searching"), ("3", "deliveringPower"), ("4", "fault"), ("5", "test"), ("6", "otherFault"), ("7", "requestingPower")]),
        valuemap("PETH-MIB::pethPsePortPowerPriority", [("1", "critical"), ("2", "high"), ("3", "low")]),
        valuemap("PETH-MIB::pethPsePortPowerClassifications", [("1", "class0"), ("2", "class1"), ("3", "class2"), ("4", "class3"), ("5", "class4")]),
        valuemap("HPE-POE-MIB::RlPoeType", [("1", "none"), ("2", "poe"), ("3", "poePlus"), ("4", "poe60w"), ("5", "poeBTType3"), ("6", "poeBTType4")]),
        valuemap("HPE-POE-MIB::powerManagementMode", [("0", "portLimit"), ("5", "classLimit"), ("6", "maxLimit")]),
        valuemap("BRIDGE-MIB::dot1dStpPortState", [("1", "disabled"), ("2", "blocking"), ("3", "listening"), ("4", "learning"), ("5", "forwarding"), ("6", "broken")]),
        valuemap("HPE-TRUNK-MIB::lacpRxState", [("1", "current"), ("2", "expired"), ("3", "defaulted"), ("4", "initialize"), ("5", "portDisabled"), ("6", "lacpDisabled")]),
        valuemap("HPE-TRUNK-MIB::lacpMuxState", [("1", "detached"), ("2", "waiting"), ("3", "attached"), ("4", "collecting"), ("5", "distributing"), ("6", "collectingDistributing")]),
        valuemap("HPE-TRUNK-MIB::lacpSelected", [("1", "unselected"), ("2", "selected"), ("3", "waiting")]),
        valuemap("HPE-STORMCTRL-MIB::trafficType", [("1", "broadcast"), ("2", "registeredMulticast"), ("3", "unregisteredMulticast"), ("4", "allMulticast"), ("5", "unknownUnicast"), ("6", "all")]),
        valuemap("HPE-STORMCTRL-MIB::rateUnit", [("1", "kbps"), ("2", "percent")]),
        valuemap("HPE-STORMCTRL-MIB::action", [("1", "none"), ("2", "trap"), ("3", "shutdown"), ("4", "trapAndShutdown")]),
        valuemap("HPE-VLAN-MIB::switchPortModeCategory", [("1", "l2"), ("2", "l3")]),
        valuemap("TruthValue", [("1", "true"), ("2", "false")]),
    ]
    for vm in new_maps:
        add_if_missing(valuemaps, vm, "name", vm.findtext("name"))

    direct_items = [
        item("PoE PSE 1: Nominal power", "poe.main.power[pethMainPsePower.1]", "1.3.6.1.2.1.105.1.3.1.1.2.1", delay="5m", history="7d", units="W", description="MIB: POWER-ETHERNET-MIB\nNominal PSE power budget.", tags_pairs=[("component", "poe")]),
        item("PoE PSE 1: Operational status", "poe.main.status[pethMainPseOperStatus.1]", "1.3.6.1.2.1.105.1.3.1.1.3.1", delay="3m", history="7d", trends="0", valuemap="PETH-MIB::pethMainPseOperStatus", description="MIB: POWER-ETHERNET-MIB\nMain PSE operational status.", tags_pairs=[("component", "poe")],
             triggers=[trigger("PoE PSE 1 is not operational", f"last(/{TEMPLATE}/poe.main.status[pethMainPseOperStatus.1])<>1", "AVERAGE", "Current state: {ITEM.LASTVALUE1}", scope="availability")]),
        item("PoE PSE 1: Consumed power", "poe.main.consumption[pethMainPseConsumptionPower.1]", "1.3.6.1.2.1.105.1.3.1.1.4.1", delay="3m", history="7d", units="W", description="MIB: POWER-ETHERNET-MIB\nMeasured PSE power usage.", tags_pairs=[("component", "poe")],
             triggers=[trigger("High PoE power usage on PSE 1", f"last(/{TEMPLATE}/poe.main.util[pethMainPseConsumptionPower.1])>{{$POE.POWER.UTIL.WARN}}", "WARNING", "Current utilization: {ITEM.LASTVALUE1}", scope="capacity")]),
        item("PoE PSE 1: Usage threshold", "poe.main.threshold[pethMainPseUsageThreshold.1]", "1.3.6.1.2.1.105.1.3.1.1.5.1", delay="15m", history="7d", units="%", description="MIB: POWER-ETHERNET-MIB\nConfigured PSE power usage threshold.", tags_pairs=[("component", "poe")]),
        item("PoE PSE 1: Power utilization", "poe.main.util[pethMainPseConsumptionPower.1]", item_type="CALCULATED", delay="3m", history="7d", value_type="FLOAT", units="%", params="last(//poe.main.consumption[pethMainPseConsumptionPower.1])*100/last(//poe.main.power[pethMainPsePower.1])", description="Calculated PoE budget utilization.", tags_pairs=[("component", "poe")]),
        item("PoE PSE 1: Controller temperature", "poe.main.temperature[rlPethMainPseTemperatureSensor.1]", "1.3.6.1.4.1.11.2.108.2.1.8.1", delay="3m", history="7d", value_type="FLOAT", units="C", description="MIB: HPE-POE-MIB\nPoE controller temperature. Value 32767 means not available.", tags_pairs=[("component", "temperature")],
             preprocessing_steps=[("DISCARD_UNCHANGED_HEARTBEAT", ["1h"])],
             triggers=[trigger("High PoE controller temperature", f"avg(/{TEMPLATE}/poe.main.temperature[rlPethMainPseTemperatureSensor.1],5m)>{{$TEMP_WARN}}", "WARNING", "Current value: {ITEM.LASTVALUE1}", scope="performance")]),
        item("STP topology changes", "stp.topology_changes[dot1dStpTopChanges.0]", "1.3.6.1.2.1.17.2.4.0", delay="3m", history="7d", description="MIB: BRIDGE-MIB\nTotal number of topology changes detected by STP.", tags_pairs=[("component", "stp")],
             preprocessing_steps=[("CHANGE_PER_SECOND", [""])],
             triggers=[trigger("Frequent STP topology changes", f"{{$STP.TOPOLOGY.CHANGE.WARN}}>0 and min(/{TEMPLATE}/stp.topology_changes[dot1dStpTopChanges.0],15m)>{{$STP.TOPOLOGY.CHANGE.WARN}}", "WARNING", "Changes/s: {ITEM.LASTVALUE1}", scope="availability")]),
        item("STP time since topology change", "stp.time_since_change[dot1dStpTimeSinceTopologyChange.0]", "1.3.6.1.2.1.17.2.3.0", delay="3m", history="7d", units="s", description="MIB: BRIDGE-MIB\nTime since last STP topology change.", tags_pairs=[("component", "stp")],
             preprocessing_steps=[("MULTIPLIER", ["0.01"])]),
        item("STP root port", "stp.root_port[dot1dStpRootPort.0]", "1.3.6.1.2.1.17.2.7.0", delay="5m", history="7d", description="MIB: BRIDGE-MIB\nCurrent STP root port.", tags_pairs=[("component", "stp")]),
        item("LLDP remote table inserts", "lldp.remote.inserts[lldpStatsRemTablesInserts.0]", "1.0.8802.1.1.2.1.2.2.0", delay="5m", history="7d", description="MIB: LLDP-MIB\nRemote systems table insertions.", tags_pairs=[("component", "lldp")], preprocessing_steps=[("CHANGE_PER_SECOND", [""])]),
        item("LLDP remote table deletes", "lldp.remote.deletes[lldpStatsRemTablesDeletes.0]", "1.0.8802.1.1.2.1.2.3.0", delay="5m", history="7d", description="MIB: LLDP-MIB\nRemote systems table deletions.", tags_pairs=[("component", "lldp")], preprocessing_steps=[("CHANGE_PER_SECOND", [""])]),
        item("Storm-control support", "stormctrl.support[rlStormCtrlRateLimSupport.0]", "1.3.6.1.4.1.11.2.77.10.0", delay="1h", history="7d", trends="0", valuemap="TruthValue", description="MIB: HPE-STORMCTRL-MIB\nWhether storm-control/rate-limit is supported.", tags_pairs=[("component", "storm-control")]),
        item("SNMP traps: PoE", 'snmptrap["(?i)(peth|poe|power.?ethernet|power.?usage)"]', item_type="SNMP_TRAP", history="2w", trends="0", value_type="LOG", description="PoE-related SNMP traps matched before fallback.", tags_pairs=[("component", "poe")],
             triggers=[trigger("PoE trap received", f'nodata(/{TEMPLATE}/snmptrap["(?i)(peth|poe|power.?ethernet|power.?usage)"],5m)=0', "WARNING", "Last trap: {ITEM.LASTVALUE1}", manual_close=True, scope="availability")]),
        item("SNMP traps: STP", 'snmptrap["(?i)(stp|rstp|spanning|topology.?change)"]', item_type="SNMP_TRAP", history="2w", trends="0", value_type="LOG", description="STP/RSTP-related SNMP traps matched before fallback.", tags_pairs=[("component", "stp")],
             triggers=[trigger("STP trap received", f'nodata(/{TEMPLATE}/snmptrap["(?i)(stp|rstp|spanning|topology.?change)"],5m)=0', "INFO", "Last trap: {ITEM.LASTVALUE1}", manual_close=True, scope="notice")]),
        item("SNMP traps: LACP", 'snmptrap["(?i)(lacp|dot3ad|trunk)"]', item_type="SNMP_TRAP", history="2w", trends="0", value_type="LOG", description="LACP/trunk-related SNMP traps matched before fallback.", tags_pairs=[("component", "lacp")],
             triggers=[trigger("LACP trap received", f'nodata(/{TEMPLATE}/snmptrap["(?i)(lacp|dot3ad|trunk)"],5m)=0', "WARNING", "Last trap: {ITEM.LASTVALUE1}", manual_close=True, scope="availability")]),
        item("SNMP traps: security", 'snmptrap["(?i)(auth|security|dot1x|radius|acl|spoof|violation)"]', item_type="SNMP_TRAP", history="2w", trends="0", value_type="LOG", description="Security-related SNMP traps matched before fallback.", tags_pairs=[("component", "security")],
             triggers=[trigger("Security trap received", f'nodata(/{TEMPLATE}/snmptrap["(?i)(auth|security|dot1x|radius|acl|spoof|violation)"],5m)=0', "AVERAGE", "Last trap: {ITEM.LASTVALUE1}", manual_close=True, scope="security")]),
    ]
    for it in direct_items:
        add_if_missing(items, it, "key", it.findtext("key"))

    legacy_traps = {
        "snmptrap[poe]": 'snmptrap["(?i)(peth|poe|power.?ethernet|power.?usage)"]',
        "snmptrap[(?i)(peth|poe|power.?ethernet|power.?usage)]": 'snmptrap["(?i)(peth|poe|power.?ethernet|power.?usage)"]',
        "snmptrap[stp]": 'snmptrap["(?i)(stp|rstp|spanning|topology.?change)"]',
        "snmptrap[(?i)(stp|rstp|spanning|topology.?change)]": 'snmptrap["(?i)(stp|rstp|spanning|topology.?change)"]',
        "snmptrap[lacp]": 'snmptrap["(?i)(lacp|dot3ad|trunk)"]',
        "snmptrap[(?i)(lacp|dot3ad|trunk)]": 'snmptrap["(?i)(lacp|dot3ad|trunk)"]',
        "snmptrap[security]": 'snmptrap["(?i)(auth|security|dot1x|radius|acl|spoof|violation)"]',
        "snmptrap[(?i)(auth|security|dot1x|radius|acl|spoof|violation)]": 'snmptrap["(?i)(auth|security|dot1x|radius|acl|spoof|violation)"]',
    }
    for trap_item in items.findall("item"):
        key_node = trap_item.find("key")
        if key_node is not None and key_node.text == "poe.main.util[pethMainPseConsumptionPower.1]":
            params_node = trap_item.find("params")
            if params_node is not None:
                params_node.text = "last(//poe.main.consumption[pethMainPseConsumptionPower.1])*100/last(//poe.main.power[pethMainPsePower.1])"
        if key_node is not None and key_node.text in legacy_traps:
            key_node.text = legacy_traps[key_node.text]
        if trap_item.findtext("type") == "SNMP_TRAP":
            params_node = trap_item.find("params")
            if params_node is not None:
                trap_item.remove(params_node)
        for expr in trap_item.findall("./triggers/trigger/expression"):
            if expr.text:
                for old, new in legacy_traps.items():
                    expr.text = expr.text.replace(old, new)
                if "min(/Aruba 1930 Switch SNMP/stp.topology_changes[dot1dStpTopChanges.0],15m)>{$STP.TOPOLOGY.CHANGE.WARN}" in expr.text and "{$STP.TOPOLOGY.CHANGE.WARN}>0" not in expr.text:
                    expr.text = "{$STP.TOPOLOGY.CHANGE.WARN}>0 and " + expr.text

    net_if_rule = None
    for existing_rule in discoveries.findall("discovery_rule"):
        if existing_rule.findtext("key") == "net.if.discovery":
            net_if_rule = existing_rule
            break
    if net_if_rule is not None:
        item_prototypes = net_if_rule.find("item_prototypes")
        for p in [
            proto("Interface {#IFNAME}({#IFALIAS}): PVID", "net.if.pvid[dot1qPvid.{#SNMPINDEX}]", "1.3.6.1.2.1.17.7.1.4.5.1.1.{#SNMPINDEX}", delay="15m", history="7d", description="MIB: Q-BRIDGE-MIB\nVLAN ID assigned to untagged or priority-tagged frames on this port.", tags_pairs=[("component", "vlan"), ("interface", "{#IFNAME}")]),
            proto("Interface {#IFNAME}({#IFALIAS}): Switchport mode", "net.if.switchport_mode[vlanSwitchPortModeCategory.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.48.64.1.1.{#SNMPINDEX}", delay="15m", history="7d", trends="0", valuemap="HPE-VLAN-MIB::switchPortModeCategory", description="MIB: HPE-VLAN-MIB\nWhether the port is operating as L2 switchport or L3 routed port.", tags_pairs=[("component", "vlan"), ("interface", "{#IFNAME}")]),
        ]:
            add_if_missing(item_prototypes, p, "key", p.findtext("key"))

    poe_protos = [
        proto("PoE port {#SNMPINDEX}: Detection status", "poe.port.detection[pethPsePortDetectionStatus.{#SNMPINDEX}]", "1.3.6.1.2.1.105.1.1.1.6.{#SNMPINDEX}", delay="3m", history="7d", trends="0", valuemap="PETH-MIB::pethPsePortDetectionStatus", description="MIB: POWER-ETHERNET-MIB\nPoE detection status for this PSE port.", tags_pairs=[("component", "poe")],
              trigger_prototypes=[trigger("PoE port {#SNMPINDEX}: Detection fault", f"last(/{TEMPLATE}/poe.port.detection[pethPsePortDetectionStatus.{{#SNMPINDEX}}])=4 or last(/{TEMPLATE}/poe.port.detection[pethPsePortDetectionStatus.{{#SNMPINDEX}}])=6", "AVERAGE", "Current state: {ITEM.LASTVALUE1}", scope="availability")]),
        proto("PoE port {#SNMPINDEX}: Actual power", "poe.port.power[pethPsePortActualPower.{#SNMPINDEX}]", "1.3.6.1.2.1.105.1.1.1.15.{#SNMPINDEX}", delay="3m", history="7d", value_type="FLOAT", units="W", description="MIB: POWER-ETHERNET-MIB\nActual power delivered by the PSE port.", tags_pairs=[("component", "poe")]),
        proto("PoE port {#SNMPINDEX}: Power limit", "poe.port.limit[rlPethPsePortOperPowerLimit.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.108.1.1.9.{#SNMPINDEX}", delay="5m", history="7d", value_type="FLOAT", units="W", description="MIB: HPE-POE-MIB\nOperational power limit per port.", tags_pairs=[("component", "poe")], preprocessing_steps=[("MULTIPLIER", ["0.001"])]),
        proto("PoE port {#SNMPINDEX}: Output power", "poe.port.output_power[rlPethPsePortOutputPower.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.108.1.1.5.{#SNMPINDEX}", delay="3m", history="7d", value_type="FLOAT", units="W", description="MIB: HPE-POE-MIB\nOutput power in mW, normalized to W.", tags_pairs=[("component", "poe")], preprocessing_steps=[("MULTIPLIER", ["0.001"])]),
        proto("PoE port {#SNMPINDEX}: Power denied counter", "poe.port.denied[pethPsePortPowerDeniedCounter.{#SNMPINDEX}]", "1.3.6.1.2.1.105.1.1.1.12.{#SNMPINDEX}", delay="3m", history="7d", description="MIB: POWER-ETHERNET-MIB\nPower denied counter.", tags_pairs=[("component", "poe")], preprocessing_steps=[("CHANGE_PER_SECOND", [""])],
              trigger_prototypes=[trigger("PoE port {#SNMPINDEX}: Power denied events", f"min(/{TEMPLATE}/poe.port.denied[pethPsePortPowerDeniedCounter.{{#SNMPINDEX}}],5m)>0", "WARNING", "Events/s: {ITEM.LASTVALUE1}", scope="availability")]),
        proto("PoE port {#SNMPINDEX}: Overload counter", "poe.port.overload[pethPsePortOverLoadCounter.{#SNMPINDEX}]", "1.3.6.1.2.1.105.1.1.1.13.{#SNMPINDEX}", delay="3m", history="7d", description="MIB: POWER-ETHERNET-MIB\nOverload counter.", tags_pairs=[("component", "poe")], preprocessing_steps=[("CHANGE_PER_SECOND", [""])],
              trigger_prototypes=[trigger("PoE port {#SNMPINDEX}: Overload events", f"min(/{TEMPLATE}/poe.port.overload[pethPsePortOverLoadCounter.{{#SNMPINDEX}}],5m)>0", "AVERAGE", "Events/s: {ITEM.LASTVALUE1}", scope="availability")]),
        proto("PoE port {#SNMPINDEX}: Short counter", "poe.port.short[pethPsePortShortCounter.{#SNMPINDEX}]", "1.3.6.1.2.1.105.1.1.1.14.{#SNMPINDEX}", delay="3m", history="7d", description="MIB: POWER-ETHERNET-MIB\nShort-circuit counter.", tags_pairs=[("component", "poe")], preprocessing_steps=[("CHANGE_PER_SECOND", [""])],
              trigger_prototypes=[trigger("PoE port {#SNMPINDEX}: Short-circuit events", f"min(/{TEMPLATE}/poe.port.short[pethPsePortShortCounter.{{#SNMPINDEX}}],5m)>0", "AVERAGE", "Events/s: {ITEM.LASTVALUE1}", scope="availability")]),
        proto("PoE port {#SNMPINDEX}: Power class", "poe.port.class[pethPsePortPowerClassifications.{#SNMPINDEX}]", "1.3.6.1.2.1.105.1.1.1.10.{#SNMPINDEX}", delay="15m", history="7d", trends="0", valuemap="PETH-MIB::pethPsePortPowerClassifications", description="MIB: POWER-ETHERNET-MIB\nDetected PD power class.", tags_pairs=[("component", "poe")]),
        proto("PoE port {#SNMPINDEX}: Link partner PoE type", "poe.port.partner_type[rlPethPsePortLinkPartnerPoeType.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.108.1.1.14.{#SNMPINDEX}", delay="15m", history="7d", trends="0", valuemap="HPE-POE-MIB::RlPoeType", description="MIB: HPE-POE-MIB\nPoE type advertised by the connected endpoint.", tags_pairs=[("component", "poe")]),
    ]
    add_if_missing(discoveries, rule("PoE ports discovery", "poe.port.discovery", "discovery[{#POE.DETECT},1.3.6.1.2.1.105.1.1.1.6]", "Discovers PoE PSE ports from POWER-ETHERNET-MIB.", poe_protos,
                                    graph_prototypes=[graph_proto("PoE port {#SNMPINDEX}: Power", ["poe.port.power[pethPsePortActualPower.{#SNMPINDEX}]", "poe.port.output_power[rlPethPsePortOutputPower.{#SNMPINDEX}]"])],
                                    filter_conditions=[("{#POE.DETECT}", "{$POE.PORT.DETECT.MATCHES}")]), "key", "poe.port.discovery")

    add_if_missing(discoveries, rule("LLDP neighbors discovery", "lldp.rem.discovery", "discovery[{#LLDP.REM.SYSNAME},1.0.8802.1.1.2.1.4.1.1.9,{#LLDP.REM.PORTID},1.0.8802.1.1.2.1.4.1.1.7,{#LLDP.REM.PORTDESC},1.0.8802.1.1.2.1.4.1.1.8,{#LLDP.REM.CHASSISID},1.0.8802.1.1.2.1.4.1.1.5]", "Discovers LLDP remote neighbors. SNMP index is LLDP timeMark.localPort.remIndex.",
                                 [
                                     proto("LLDP neighbor {#LLDP.REM.SYSNAME}: Remote port", "lldp.rem.port_id[lldpRemPortId.{#SNMPINDEX}]", "1.0.8802.1.1.2.1.4.1.1.7.{#SNMPINDEX}", delay="15m", history="7d", trends="0", value_type="CHAR", description="MIB: LLDP-MIB\nRemote LLDP port ID.", tags_pairs=[("component", "lldp")]),
                                     proto("LLDP neighbor {#LLDP.REM.SYSNAME}: Remote port description", "lldp.rem.port_desc[lldpRemPortDesc.{#SNMPINDEX}]", "1.0.8802.1.1.2.1.4.1.1.8.{#SNMPINDEX}", delay="15m", history="7d", trends="0", value_type="CHAR", description="MIB: LLDP-MIB\nRemote LLDP port description.", tags_pairs=[("component", "lldp")]),
                                     proto("LLDP neighbor {#LLDP.REM.SYSNAME}: System name", "lldp.rem.sysname[lldpRemSysName.{#SNMPINDEX}]", "1.0.8802.1.1.2.1.4.1.1.9.{#SNMPINDEX}", delay="15m", history="7d", trends="0", value_type="CHAR", description="MIB: LLDP-MIB\nRemote LLDP system name.", tags_pairs=[("component", "lldp")],
                                           trigger_prototypes=[trigger("LLDP neighbor changed or disappeared: {#LLDP.REM.SYSNAME}", f"{{$LLDP.NEIGHBOR.CHANGE}}=1 and change(/{TEMPLATE}/lldp.rem.sysname[lldpRemSysName.{{#SNMPINDEX}}])=1", "INFO", "Current neighbor: {ITEM.LASTVALUE1}", manual_close=True, scope="notice")]),
                                 ],
                                 filter_conditions=[("{#LLDP.REM.SYSNAME}", "{$LLDP.REM.SYSNAME.MATCHES}"), ("{#LLDP.REM.SYSNAME}", "{$LLDP.REM.SYSNAME.NOT_MATCHES}", "NOT_MATCHES_REGEX")]), "key", "lldp.rem.discovery")

    add_if_missing(discoveries, rule("STP ports discovery", "stp.port.discovery", "discovery[{#BRIDGE.IFINDEX},1.3.6.1.2.1.17.1.4.1.2]", "Discovers bridge ports for STP state monitoring.",
                                 [
                                     proto("STP bridge port {#SNMPINDEX}: State", "stp.port.state[dot1dStpPortState.{#SNMPINDEX}]", "1.3.6.1.2.1.17.2.15.1.3.{#SNMPINDEX}", delay="3m", history="7d", trends="0", valuemap="BRIDGE-MIB::dot1dStpPortState", description="MIB: BRIDGE-MIB\nSTP state for bridge port.", tags_pairs=[("component", "stp")],
                                           trigger_prototypes=[trigger("STP bridge port {#SNMPINDEX}: broken state", f"last(/{TEMPLATE}/stp.port.state[dot1dStpPortState.{{#SNMPINDEX}}])=6", "AVERAGE", "Current state: {ITEM.LASTVALUE1}", scope="availability")]),
                                     proto("STP bridge port {#SNMPINDEX}: Forward transitions", "stp.port.forward_transitions[dot1dStpPortForwardTransitions.{#SNMPINDEX}]", "1.3.6.1.2.1.17.2.15.1.10.{#SNMPINDEX}", delay="5m", history="7d", description="MIB: BRIDGE-MIB\nForwarding transition rate.", tags_pairs=[("component", "stp")], preprocessing_steps=[("CHANGE_PER_SECOND", [""])]),
                                 ]), "key", "stp.port.discovery")

    add_if_missing(discoveries, rule("VLAN discovery", "vlan.discovery", "discovery[{#VLAN.NAME},1.3.6.1.2.1.17.7.1.4.3.1.1]", "Discovers static VLANs from Q-BRIDGE-MIB.",
                                 [
                                     proto("VLAN {#SNMPINDEX}: Name", "vlan.name[dot1qVlanStaticName.{#SNMPINDEX}]", "1.3.6.1.2.1.17.7.1.4.3.1.1.{#SNMPINDEX}", delay="1h", history="7d", trends="0", value_type="CHAR", description="MIB: Q-BRIDGE-MIB\nStatic VLAN name.", tags_pairs=[("component", "vlan")]),
                                     proto("VLAN {#SNMPINDEX}: Egress ports bitmap", "vlan.egress[dot1qVlanStaticEgressPorts.{#SNMPINDEX}]", "1.3.6.1.2.1.17.7.1.4.3.1.2.{#SNMPINDEX}", delay="1h", history="7d", trends="0", value_type="CHAR", description="MIB: Q-BRIDGE-MIB\nStatic VLAN egress port bitmap.", tags_pairs=[("component", "vlan")]),
                                 ],
                                 filter_conditions=[("{#VLAN.NAME}", "{$VLAN.NAME.MATCHES}"), ("{#VLAN.NAME}", "{$VLAN.NAME.NOT_MATCHES}", "NOT_MATCHES_REGEX")]), "key", "vlan.discovery")

    add_if_missing(discoveries, rule("LACP ports discovery", "lacp.port.discovery", "discovery[{#LACP.RXSTATE},1.3.6.1.4.1.11.2.65.8.1.3]", "Discovers LACP aggregation ports from HPE-TRUNK-MIB.",
                                 [
                                     proto("LACP port {#SNMPINDEX}: RX state", "lacp.port.rx_state[rlDot3adAggPortLacpRxState.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.65.8.1.3.{#SNMPINDEX}", delay="3m", history="7d", trends="0", valuemap="HPE-TRUNK-MIB::lacpRxState", description="MIB: HPE-TRUNK-MIB\nLACP receive state.", tags_pairs=[("component", "lacp")],
                                           trigger_prototypes=[trigger("LACP port {#SNMPINDEX}: RX state is not current", f"{{$LACP.MONITOR}}=1 and last(/{TEMPLATE}/lacp.port.rx_state[rlDot3adAggPortLacpRxState.{{#SNMPINDEX}}])<>1", "WARNING", "Current state: {ITEM.LASTVALUE1}", scope="availability")]),
                                     proto("LACP port {#SNMPINDEX}: MUX state", "lacp.port.mux_state[rlDot3adAggPortLacpMuxState.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.65.8.1.4.{#SNMPINDEX}", delay="3m", history="7d", trends="0", valuemap="HPE-TRUNK-MIB::lacpMuxState", description="MIB: HPE-TRUNK-MIB\nLACP MUX state.", tags_pairs=[("component", "lacp")]),
                                     proto("LACP port {#SNMPINDEX}: Selected state", "lacp.port.selected[rlDot3adAggPortLacpSelected.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.65.8.1.6.{#SNMPINDEX}", delay="3m", history="7d", trends="0", valuemap="HPE-TRUNK-MIB::lacpSelected", description="MIB: HPE-TRUNK-MIB\nLACP selected state.", tags_pairs=[("component", "lacp")],
                                           trigger_prototypes=[trigger("LACP port {#SNMPINDEX}: not selected", f"{{$LACP.MONITOR}}=1 and last(/{TEMPLATE}/lacp.port.selected[rlDot3adAggPortLacpSelected.{{#SNMPINDEX}}])<>2", "WARNING", "Current state: {ITEM.LASTVALUE1}", scope="availability")]),
                                     proto("LACP port {#SNMPINDEX}: LACPDUs RX", "lacp.port.pdus_rx[rlDot3adAggPortLacpPdusRx.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.65.8.1.1.{#SNMPINDEX}", delay="3m", history="7d", description="MIB: HPE-TRUNK-MIB\nReceived LACPDUs per second.", tags_pairs=[("component", "lacp")], preprocessing_steps=[("CHANGE_PER_SECOND", [""])]),
                                     proto("LACP port {#SNMPINDEX}: LACPDUs TX", "lacp.port.pdus_tx[rlDot3adAggPortLacpPDUsTx.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.65.8.1.2.{#SNMPINDEX}", delay="3m", history="7d", description="MIB: HPE-TRUNK-MIB\nTransmitted LACPDUs per second.", tags_pairs=[("component", "lacp")], preprocessing_steps=[("CHANGE_PER_SECOND", [""])]),
                                 ],
                                 filter_conditions=[("{#LACP.RXSTATE}", "{$LACP.RXSTATE.MATCHES}")]), "key", "lacp.port.discovery")

    add_if_missing(discoveries, rule("Storm-control discovery", "stormctrl.discovery", "discovery[{#STORM.TRAFFIC},1.3.6.1.4.1.11.2.77.12.1.1]", "Discovers storm-control/rate-limit entries by bridge port and traffic type.",
                                 [
                                     proto("Storm-control {#SNMPINDEX}: Traffic type", "stormctrl.traffic[rlStormCtrlRateLimCfgTraffic.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.77.12.1.1.{#SNMPINDEX}", delay="15m", history="7d", trends="0", valuemap="HPE-STORMCTRL-MIB::trafficType", description="MIB: HPE-STORMCTRL-MIB\nConfigured traffic type.", tags_pairs=[("component", "storm-control")]),
                                     proto("Storm-control {#SNMPINDEX}: Rate", "stormctrl.rate[rlStormCtrlRateLimCfgRate.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.77.12.1.2.{#SNMPINDEX}", delay="15m", history="7d", description="MIB: HPE-STORMCTRL-MIB\nConfigured storm-control rate.", tags_pairs=[("component", "storm-control")]),
                                     proto("Storm-control {#SNMPINDEX}: Unit", "stormctrl.unit[rlStormCtrlRateLimCfgUnit.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.77.12.1.3.{#SNMPINDEX}", delay="15m", history="7d", trends="0", valuemap="HPE-STORMCTRL-MIB::rateUnit", description="MIB: HPE-STORMCTRL-MIB\nConfigured rate unit.", tags_pairs=[("component", "storm-control")]),
                                     proto("Storm-control {#SNMPINDEX}: Action", "stormctrl.action[rlStormCtrlRateLimCfgAction.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.77.12.1.4.{#SNMPINDEX}", delay="15m", history="7d", trends="0", valuemap="HPE-STORMCTRL-MIB::action", description="MIB: HPE-STORMCTRL-MIB\nConfigured storm-control action.", tags_pairs=[("component", "storm-control")]),
                                     proto("Storm-control {#SNMPINDEX}: Drops", "stormctrl.drops[rlStormCtrlRateLimOperDropCnt.{#SNMPINDEX}]", "1.3.6.1.4.1.11.2.77.13.1.2.{#SNMPINDEX}", delay="3m", history="7d", description="MIB: HPE-STORMCTRL-MIB\nStorm-control dropped traffic per second.", tags_pairs=[("component", "storm-control")], preprocessing_steps=[("CHANGE_PER_SECOND", [""])],
                                           trigger_prototypes=[trigger("Storm-control drops detected on {#SNMPINDEX}", f"{{$STORMCTRL.MONITOR}}=1 and min(/{TEMPLATE}/stormctrl.drops[rlStormCtrlRateLimOperDropCnt.{{#SNMPINDEX}}],5m)>0", "WARNING", "Drops/s: {ITEM.LASTVALUE1}", scope="performance")]),
                                 ]), "key", "stormctrl.discovery")

    macro_values = {
        "{$POE.POWER.UTIL.WARN}": ("80", "Warn when PoE power budget usage exceeds this percentage."),
        "{$POE.POWER.UTIL.CRIT}": ("90", "Critical PoE power budget percentage for site-specific overrides."),
        "{$POE.PORT.DETECT.MATCHES}": ("^(3|4|6|7)$", "Discover PoE ports delivering, requesting or reporting faults."),
        "{$POE.PORT.UTIL.WARN}": ("85", "Reserved per-port PoE utilization threshold."),
        "{$LLDP.NEIGHBOR.CHANGE}": ("0", "Set to 1 to alert when discovered LLDP neighbor names change."),
        "{$LLDP.REM.SYSNAME.MATCHES}": (".+", "Discover LLDP neighbors with a system name."),
        "{$LLDP.REM.SYSNAME.NOT_MATCHES}": ("CHANGE_IF_NEEDED", "Optional LLDP neighbor exclusion regex."),
        "{$STP.TOPOLOGY.CHANGE.WARN}": ("0", "Topology change rate threshold. Raise above 0 to enable meaningful alerts."),
        "{$LACP.MONITOR}": ("1", "Set to 0 to suppress LACP state triggers."),
        "{$LACP.RXSTATE.MATCHES}": ("^.*$", "Discover all LACP RX states."),
        "{$VLAN.NAME.MATCHES}": (".*", "Discover VLANs matching this name regex."),
        "{$VLAN.NAME.NOT_MATCHES}": ("CHANGE_IF_NEEDED", "Optional VLAN name exclusion regex."),
        "{$STORMCTRL.MONITOR}": ("0", "Set to 1 to alert on storm-control drops."),
    }
    for name, (value, desc) in macro_values.items():
        if not any(m.findtext("macro") == name for m in macros.findall("macro")):
            macros.append(e("macro", children=[e("macro", name), e("value", value), e("description", desc)]))

    dedupe(items, "item", "key")
    dedupe(discoveries, "discovery_rule", "key")
    dedupe(valuemaps, "valuemap", "name")
    dedupe(macros, "macro", "macro")

    ET.indent(tree, space="    ")
    tree.write(XML_PATH, encoding="UTF-8", xml_declaration=True)


if __name__ == "__main__":
    main()
