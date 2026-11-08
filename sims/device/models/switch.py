# SPDX-License-Identifier: GPL-3.0-or-later
"""Access switch (Cisco Catalyst 2960-X style sysObjectID) exposing standard
IF-MIB (ifTable + ifXTable) and ENTITY-MIB/ENTITY-SENSOR-MIB (RFC 3433).

snmpd's own IF-MIB modules are disabled for this model so the synthetic
interfaces are the only ones. Octet counters run fast enough that Counter32
ifInOctets/ifOutOctets wrap every few minutes; ifHC* Counter64 keep counting
(ifInOctets == ifHCInOctets mod 2^32). The Te1/0/1 HC counters carry a 2^60
offset so they exceed 2^53 (exercises exact Counter64 handling).
"""

from simcore import (Model, Obj, Var, wave, rint, ramp_counter, check_str,
                     str_from_hex, TWO32, TWO64, NULL)

IFM = "IF-MIB"
ENT = "ENTITY-MIB"
ESM = "ENTITY-SENSOR-MIB"
IFT = "1.3.6.1.2.1.2.2.1"
IFX = "1.3.6.1.2.1.31.1.1.1"
EPT = "1.3.6.1.2.1.47.1.1.1.1"
EST = "1.3.6.1.2.1.99.1.1.1"

UPDOWN = {1: "up", 2: "down", 3: "testing"}
OPER = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent",
        7: "lowerLayerDown"}
TRUTH = {1: "true", 2: "false"}
PHYS_CLASS = {1: "other", 2: "unknown", 3: "chassis", 4: "backplane", 5: "container",
              6: "powerSupply", 7: "fan", 8: "sensor", 9: "module", 10: "port",
              11: "stack", 12: "cpu"}
SENSOR_TYPE = {1: "other", 2: "unknown", 3: "voltsAC", 4: "voltsDC", 5: "amperes",
               6: "watts", 7: "hertz", 8: "celsius", 9: "percentRH", 10: "rpm",
               11: "cmm", 12: "truthvalue"}
SENSOR_SCALE = {1: "yocto", 2: "zepto", 3: "atto", 4: "femto", 5: "pico", 6: "nano",
                7: "micro", 8: "milli", 9: "units", 10: "kilo", 11: "mega", 12: "giga",
                13: "tera", 14: "exa", 15: "peta", 16: "zetta", 17: "yotta"}
SENSOR_STATUS = {1: "ok", 2: "unavailable", 3: "nonoperational"}
# RFC 3433 SensorDataScale exponents (note exa/peta are swapped in the MIB order)
SCALE_EXP = {1: -24, 2: -21, 3: -18, 4: -15, 5: -12, 6: -9, 7: -6, 8: -3, 9: 0,
             10: 3, 11: 6, 12: 9, 13: 12, 14: 18, 15: 15, 16: 21, 17: 24}
TYPE_UNITS = {3: "V", 4: "V", 5: "A", 6: "W", 7: "Hz", 8: "degC", 9: "%RH", 10: "rpm"}

O = {}


def o(mib, name, oid, typ, units=None, enum=None, **kw):
    O[name] = Obj(mib, name, oid, typ, units=units, enum=enum, **kw)
    return O[name]


o(IFM, "ifNumber", "1.3.6.1.2.1.2.1", "Integer")
o(IFM, "ifIndex", IFT + ".1", "Integer")
o(IFM, "ifDescr", IFT + ".2", "OctetString")
o(IFM, "ifType", IFT + ".3", "Integer")
o(IFM, "ifMtu", IFT + ".4", "Integer", "By")
o(IFM, "ifSpeed", IFT + ".5", "Gauge32", "bit/s")
o(IFM, "ifPhysAddress", IFT + ".6", "OctetString")
o(IFM, "ifAdminStatus", IFT + ".7", "Integer", enum=UPDOWN)
o(IFM, "ifOperStatus", IFT + ".8", "Integer", enum=OPER)
o(IFM, "ifLastChange", IFT + ".9", "TimeTicks", "s")
o(IFM, "ifInOctets", IFT + ".10", "Counter32", "octets")
o(IFM, "ifInUcastPkts", IFT + ".11", "Counter32", "packets")
o(IFM, "ifInDiscards", IFT + ".13", "Counter32", "packets")
o(IFM, "ifInErrors", IFT + ".14", "Counter32", "packets")
o(IFM, "ifOutOctets", IFT + ".16", "Counter32", "octets")
o(IFM, "ifOutUcastPkts", IFT + ".17", "Counter32", "packets")
o(IFM, "ifOutErrors", IFT + ".20", "Counter32", "packets")
o(IFM, "ifName", IFX + ".1", "OctetString")
o(IFM, "ifHCInOctets", IFX + ".6", "Counter64", "octets")
o(IFM, "ifHCInUcastPkts", IFX + ".7", "Counter64", "packets")
o(IFM, "ifHCOutOctets", IFX + ".10", "Counter64", "octets")
o(IFM, "ifHCOutUcastPkts", IFX + ".11", "Counter64", "packets")
o(IFM, "ifHighSpeed", IFX + ".15", "Gauge32", "Mbit/s")
o(IFM, "ifConnectorPresent", IFX + ".17", "Integer", enum=TRUTH)
o(IFM, "ifAlias", IFX + ".18", "OctetString", writable=True, check=check_str(64))
o(ENT, "entPhysicalDescr", EPT + ".2", "OctetString")
o(ENT, "entPhysicalVendorType", EPT + ".3", "OID")
o(ENT, "entPhysicalContainedIn", EPT + ".4", "Integer")
o(ENT, "entPhysicalClass", EPT + ".5", "Integer", enum=PHYS_CLASS)
o(ENT, "entPhysicalParentRelPos", EPT + ".6", "Integer")
o(ENT, "entPhysicalName", EPT + ".7", "OctetString")
o(ESM, "entPhySensorType", EST + ".1", "Integer", enum=SENSOR_TYPE)
o(ESM, "entPhySensorScale", EST + ".2", "Integer", enum=SENSOR_SCALE)
o(ESM, "entPhySensorPrecision", EST + ".3", "Integer")
o(ESM, "entPhySensorValue", EST + ".4", "Integer")
o(ESM, "entPhySensorOperStatus", EST + ".5", "Integer", enum=SENSOR_STATUS)
o(ESM, "entPhySensorUnitsDisplay", EST + ".6", "OctetString")
o(ESM, "entPhySensorValueUpdateRate", EST + ".8", "Gauge32", "ms")

LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
CEV = "CISCO-ENTITY-VENDORTYPE-OID-MIB"
REF_OBJECTS = [
    Obj("IF-MIB", "linkDown", LINK_DOWN, "OID"),
    Obj("CISCO-PRODUCTS-MIB", "cat29xxStack", "1.3.6.1.4.1.9.1.1208", "OID"),
    Obj(CEV, "cevChassisWsC2960x48fpdL", "1.3.6.1.4.1.9.12.3.1.3.1259", "OID"),
    Obj(CEV, "cevSensorTempsensor", "1.3.6.1.4.1.9.12.3.1.8.137", "OID"),
    Obj(CEV, "cevSensorModuleHotSpotTemp", "1.3.6.1.4.1.9.12.3.1.8.142", "OID"),
    Obj(CEV, "cevSensorVoltagesensor", "1.3.6.1.4.1.9.12.3.1.8.135", "OID"),
    Obj(CEV, "cevSensorCursensor", "1.3.6.1.4.1.9.12.3.1.8.136", "OID"),
    Obj(CEV, "cevSensorPowersensor", "1.3.6.1.4.1.9.12.3.1.8.141", "OID"),
    Obj(CEV, "cevSensorFanSpeedsensor", "1.3.6.1.4.1.9.12.3.1.8.139", "OID"),
]
VT = {x.name: x.oid for x in REF_OBJECTS}
ZERO_DOT_ZERO = "0.0"   # SNMPv2-SMI zeroDotZero: vendor type unknown

# ifIndex -> (name, descr, type, mtu, speed_bps, admin, oper, rate B/s, alias, hc offset)
IFACES = [
    (1, "Vl1", "Vlan1", 53, 1500, 1_000_000_000, 1, 1, 40_000.0, "mgmt", 0),
    (10101, "Gi1/0/1", "GigabitEthernet1/0/1", 6, 1500, 1_000_000_000, 1, 1, 31_000_000.0,
     "uplink core-1", 0),
    (10102, "Gi1/0/2", "GigabitEthernet1/0/2", 6, 1500, 1_000_000_000, 1, 1, 22_000_000.0,
     "ups-a1 nmc", 0),
    (10103, "Gi1/0/3", "GigabitEthernet1/0/3", 6, 1500, 1_000_000_000, 1, 2, 9_000_000.0,
     "", 0),
    (10104, "Gi1/0/4", "GigabitEthernet1/0/4", 6, 1500, 1_000_000_000, 2, 2, 0.0, "spare", 0),
    (10601, "Te1/0/1", "TenGigabitEthernet1/0/1", 6, 9216, 10_000_000_000, 1, 1,
     48_000_000.0, "uplink core-2", 1 << 60),
]
LINK_DOWN_AT = 3_000_000.0   # seconds after boot when Gi1/0/3 went down

# entPhysicalIndex -> (descr, name, class, containedIn, relpos, vendorType)
PHYS = [
    (1001, "WS-C2960X-48FPD-L", "Switch 1", 3, 0, -1, VT["cevChassisWsC2960x48fpdL"]),
    (1005, "Switch 1 - Inlet Temp Sensor", "Inlet Temp", 8, 1001, 1, VT["cevSensorTempsensor"]),
    (1006, "Switch 1 - Hotspot Temp Sensor", "Hotspot Temp", 8, 1001, 2,
     VT["cevSensorModuleHotSpotTemp"]),
    (1010, "PS-1 Output Voltage", "PS-1 Vout", 8, 1001, 3, VT["cevSensorVoltagesensor"]),
    (1011, "PS-1 Output Current", "PS-1 Iout", 8, 1001, 4, VT["cevSensorCursensor"]),
    (1012, "PS-1 Input Power", "PS-1 Pin", 8, 1001, 5, VT["cevSensorPowersensor"]),
    (1020, "Fan 1 Speed", "Fan 1", 8, 1001, 6, VT["cevSensorFanSpeedsensor"]),
    (1021, "Fan 2 Speed", "Fan 2", 8, 1001, 7, VT["cevSensorFanSpeedsensor"]),
    (1030, "Inlet Humidity Sensor", "Inlet RH", 8, 1001, 8, ZERO_DOT_ZERO),
    (1040, "Te1/0/1 Module Supply Voltage", "Te1/0/1 Vcc", 8, 1001, 9, VT["cevSensorVoltagesensor"]),
    (1041, "Te1/0/1 Module Tx Bias Current", "Te1/0/1 Bias", 8, 1001, 10, VT["cevSensorCursensor"]),
]


def sensor_defs(t, step):
    """entPhysicalIndex -> (type, scale, precision, physical value or None, status, display)."""
    return {
        1005: (8, 9, 1, wave("t1", t, 27.0, 1.5, 3600, 0.1, step), 1, "C"),
        1006: (8, 9, 0, wave("t2", t, 41.0, 3.0, 2400, 0.3, step), 1, "C"),
        1010: (4, 8, 0, wave("v1", t, 12.03, 0.02, 600, 0.004, step), 1, "V"),
        1011: (5, 9, 2, wave("i1", t, 4.5, 0.6, 1800, 0.03, step), 1, "A"),
        1012: (6, 9, 0, wave("p1", t, 58.0, 7.0, 1800, 0.5, step), 1, "W"),
        1020: (10, 9, 0, wave("f1", t, 7400.0, 300.0, 900, 25.0, step), 1, "rpm"),
        1021: (10, 9, 0, None, 3, "rpm"),
        1030: (9, 9, 1, wave("rh", t, 38.0, 4.0, 5000, 0.4, step), 1, "%RH"),
        1040: (4, 7, 0, wave("vcc", t, 3.297, 0.01, 700, 0.002, step), 1, "V"),
        1041: (5, 8, 1, wave("bias", t, 0.0065, 0.0004, 1300, 0.0001, step), 1, "A"),
    }


def mac(i):
    return bytes([0x70, 0x0f, 0x6a, 0x3c, (i >> 8) & 0xff, i & 0xff])


class Switch(Model):
    name = "cisco-2960x"
    sysObjectID = "1.3.6.1.4.1.9.1.1208"
    sysDescr = ("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
                "Version 15.2(7)E8, RELEASE SOFTWARE (fc3)")
    sysName = "sw-a1"
    contact = "netops@example.com"
    location = "DC1 Row A Rack 1 U42"
    objects = list(O.values())
    ref_objects = REF_OBJECTS
    pass_roots = ["1.3.6.1.2.1.2", "1.3.6.1.2.1.31", "1.3.6.1.2.1.47", "1.3.6.1.2.1.99"]
    snmpd_exclude = ["ifTable", "ifXTable", "interfaces", "if-mib"]
    trap_oid = LINK_DOWN

    def sample(self, step):
        t = max(0.0, self.t_of(step))
        V = []

        def add(name, idx, raw, eng=None, units=None):
            V.append(Var(O[name], idx, raw, eng, units))

        add("ifNumber", 0, len(IFACES), len(IFACES))
        for (ix, nm, descr, typ, mtu, speed, adm, oper, rate, alias, off) in IFACES:
            tc = t if oper == 1 else min(t, LINK_DOWN_AT)
            if adm == 2:
                tc = 0.0
            hin = off + ramp_counter("in%d" % ix, tc, rate)
            hout = off + ramp_counter("out%d" % ix, tc, rate * 0.37)
            pin = ramp_counter("pin%d" % ix, tc, rate / 820.0)
            pout = ramp_counter("pout%d" % ix, tc, rate * 0.37 / 610.0)
            errs = int(tc // 86_400) * 3
            alias_now = str_from_hex(self.state.get("%s.%d" % (O["ifAlias"].oid, ix),
                                                    alias.encode().hex()))
            add("ifIndex", ix, ix)
            add("ifDescr", ix, descr)
            add("ifType", ix, typ, typ)
            add("ifMtu", ix, mtu, mtu)
            add("ifSpeed", ix, min(speed, TWO32 - 1), min(speed, TWO32 - 1))
            add("ifPhysAddress", ix, mac(ix))
            add("ifAdminStatus", ix, adm, adm)
            add("ifOperStatus", ix, oper, oper)
            lc = rint((LINK_DOWN_AT if (oper == 2 and adm == 1) else 412.0) * 100) % TWO32
            add("ifLastChange", ix, lc, lc / 100.0)
            add("ifInOctets", ix, hin % TWO32, hin % TWO32)
            add("ifInUcastPkts", ix, pin % TWO32, pin % TWO32)
            add("ifInDiscards", ix, errs // 3, errs // 3)
            add("ifInErrors", ix, errs, errs)
            add("ifOutOctets", ix, hout % TWO32, hout % TWO32)
            add("ifOutUcastPkts", ix, pout % TWO32, pout % TWO32)
            add("ifOutErrors", ix, 0, 0)
            add("ifName", ix, nm)
            add("ifHCInOctets", ix, hin % TWO64, hin % TWO64)
            add("ifHCInUcastPkts", ix, pin, pin)
            add("ifHCOutOctets", ix, hout % TWO64, hout % TWO64)
            add("ifHCOutUcastPkts", ix, pout, pout)
            add("ifHighSpeed", ix, speed // 1_000_000, speed // 1_000_000)
            cp = 2 if typ == 53 else 1
            add("ifConnectorPresent", ix, cp, cp)
            add("ifAlias", ix, alias_now)

        for (ix, descr, name, cls, cont, pos, vt) in PHYS:
            add("entPhysicalDescr", ix, descr)
            add("entPhysicalVendorType", ix, vt)
            add("entPhysicalContainedIn", ix, cont if cont else 0)
            add("entPhysicalClass", ix, cls, cls)
            add("entPhysicalParentRelPos", ix, pos)
            add("entPhysicalName", ix, name)

        for ix, (typ, scale, prec, phys, status, disp) in sorted(sensor_defs(t, step).items()):
            mult = 10.0 ** SCALE_EXP[scale]
            if phys is None:
                raw, eng = 0, None
            else:
                raw = rint(phys / mult * 10 ** prec)
                eng = raw * mult / 10 ** prec
            add("entPhySensorType", ix, typ, typ)
            add("entPhySensorScale", ix, scale, scale)
            add("entPhySensorPrecision", ix, prec, prec)
            V.append(Var(O["entPhySensorValue"], ix, raw,
                         eng if eng is not None else NULL, TYPE_UNITS.get(typ)))
            add("entPhySensorOperStatus", ix, status, status)
            add("entPhySensorUnitsDisplay", ix, disp)
            add("entPhySensorValueUpdateRate", ix, self.step_ms, self.step_ms)
        return V

    def trap_varbinds(self, step):
        ix = 10103
        return [
            ("%s.%d" % (O["ifIndex"].oid, ix), "Integer", ix),
            ("%s.%d" % (O["ifAdminStatus"].oid, ix), "Integer", 1),
            ("%s.%d" % (O["ifOperStatus"].oid, ix), "Integer", 2),
        ]
