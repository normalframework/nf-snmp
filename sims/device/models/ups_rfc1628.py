# SPDX-License-Identifier: GPL-3.0-or-later
"""Generic three-phase UPS speaking only the standard UPS-MIB (RFC 1628),
from an unknown vendor (sysObjectID under the unassigned enterprise 99999).

Scaling per RFC 1628: frequencies in 0.1 Hz, currents in 0.1 A RMS, battery
voltage in 0.1 V DC, voltages/power in whole units.
"""

from simcore import Model, Obj, Var, wave, rint, noise

M = "UPS-MIB"
B = "1.3.6.1.2.1.33.1"

BATT_STATUS = {1: "unknown", 2: "batteryNormal", 3: "batteryLow", 4: "batteryDepleted"}
OUT_SOURCE = {1: "other", 2: "none", 3: "normal", 4: "bypass", 5: "battery",
              6: "booster", 7: "reducer"}

O = {}


def o(name, sub, typ, units=None, enum=None):
    O[name] = Obj(M, name, "%s.%s" % (B, sub), typ, units=units, enum=enum)
    return O[name]


o("upsIdentManufacturer", "1.1", "OctetString")
o("upsIdentModel", "1.2", "OctetString")
o("upsIdentUPSSoftwareVersion", "1.3", "OctetString")
o("upsIdentAgentSoftwareVersion", "1.4", "OctetString")
o("upsIdentName", "1.5", "OctetString")
o("upsBatteryStatus", "2.1", "Integer", enum=BATT_STATUS)
o("upsSecondsOnBattery", "2.2", "Integer", "s")
o("upsEstimatedMinutesRemaining", "2.3", "Integer", "min")
o("upsEstimatedChargeRemaining", "2.4", "Integer", "%")
o("upsBatteryVoltage", "2.5", "Integer", "V")
o("upsBatteryCurrent", "2.6", "Integer", "A")
o("upsBatteryTemperature", "2.7", "Integer", "degC")
o("upsInputLineBads", "3.1", "Counter32")
o("upsInputNumLines", "3.2", "Integer")
o("upsInputLineIndex", "3.3.1.1", "Integer")
o("upsInputFrequency", "3.3.1.2", "Integer", "Hz")
o("upsInputVoltage", "3.3.1.3", "Integer", "V")
o("upsInputCurrent", "3.3.1.4", "Integer", "A")
o("upsInputTruePower", "3.3.1.5", "Integer", "W")
o("upsOutputSource", "4.1", "Integer", enum=OUT_SOURCE)
o("upsOutputFrequency", "4.2", "Integer", "Hz")
o("upsOutputNumLines", "4.3", "Integer")
o("upsOutputLineIndex", "4.4.1.1", "Integer")
o("upsOutputVoltage", "4.4.1.2", "Integer", "V")
o("upsOutputCurrent", "4.4.1.3", "Integer", "A")
o("upsOutputPower", "4.4.1.4", "Integer", "W")
o("upsOutputPercentLoad", "4.4.1.5", "Integer", "%")
o("upsAlarmsPresent", "6.1", "Gauge32")

# upsTrapOnBattery NOTIFICATION-TYPE ::= { upsTraps 1 }, upsTraps = upsMIB 2
TRAP_ON_BATTERY = "1.3.6.1.2.1.33.2.1"
UPS_CONFIG_LOW_BATT_TIME = "1.3.6.1.2.1.33.1.9.7.0"
REF_OBJECTS = [
    Obj(M, "upsTrapOnBattery", TRAP_ON_BATTERY, "OID"),
    Obj(M, "upsConfigLowBattTime", "1.3.6.1.2.1.33.1.9.7", "Integer"),
]


class UpsRfc1628(Model):
    name = "ups-rfc1628"
    sysObjectID = "1.3.6.1.4.1.99999.1.1"
    sysDescr = "Generic UPS SNMP Adapter v2.1.4 (UPS-MIB RFC 1628)"
    sysName = "ups-b2"
    contact = "facilities@example.com"
    location = "DC1 Electrical Room"
    objects = list(O.values())
    ref_objects = REF_OBJECTS
    pass_roots = ["1.3.6.1.2.1.33"]
    trap_oid = TRAP_ON_BATTERY

    def sample(self, step):
        t = self.t_of(step)
        V = []

        def add(name, raw, eng=None, index=0):
            V.append(Var(O[name], index, raw, eng))

        def scaled(name, x, div, index=0):
            r = rint(x * div)
            add(name, r, r / float(div), index)

        add("upsIdentManufacturer", "Acme Power Systems")
        add("upsIdentModel", "APS-30K 3PH")
        add("upsIdentUPSSoftwareVersion", "3.04")
        add("upsIdentAgentSoftwareVersion", "SNMP-AG 2.1.4")
        add("upsIdentName", "UPS-B2")
        cap = wave("cap", t, 98.5, 1.2, 5400, 0.0, step)
        cap = min(100.0, cap)
        add("upsBatteryStatus", 2, 2)
        add("upsSecondsOnBattery", 0, 0.0)
        mins = rint(42.0 * cap / 100.0 + noise("mins", step))
        add("upsEstimatedMinutesRemaining", mins, float(mins))
        c = rint(cap)
        add("upsEstimatedChargeRemaining", c, float(c))
        scaled("upsBatteryVoltage", wave("vb", t, 545.0, 1.5, 1200, 0.3, step), 10)
        scaled("upsBatteryCurrent", wave("ib", t, 0.4, 0.3, 600, 0.05, step), 10)
        bt = rint(wave("bt", t, 24.0, 1.5, 7200, 0.2, step))
        add("upsBatteryTemperature", bt, float(bt))
        # a power blip roughly every 2 hours bumps upsInputLineBads
        bads = 3 + int(max(0.0, t) // 7200)
        add("upsInputLineBads", bads, bads)
        add("upsInputNumLines", 3, 3)
        for ph in (1, 2, 3):
            add("upsInputLineIndex", ph, None, ph)
            scaled("upsInputFrequency", wave("fin", t, 60.0, 0.04, 300, 0.02, step), 10, ph)
            v = rint(wave("vin%d" % ph, t, 277.0, 3.0, 900, 0.8, step))
            add("upsInputVoltage", v, float(v), ph)
            i = wave("iin%d" % ph, t, 26.0 + 2 * ph, 4.0, 1800, 0.5, step)
            scaled("upsInputCurrent", i, 10, ph)
            p = rint(v * i * 0.97)
            add("upsInputTruePower", p, float(p), ph)
        add("upsOutputSource", 3, 3)
        scaled("upsOutputFrequency", wave("fout", t, 60.0, 0.01, 300, 0.01, step), 10)
        add("upsOutputNumLines", 3, 3)
        for ph in (1, 2, 3):
            add("upsOutputLineIndex", ph, None, ph)
            v = rint(wave("vout%d" % ph, t, 277.0, 0.8, 600, 0.3, step))
            add("upsOutputVoltage", v, float(v), ph)
            i = wave("iout%d" % ph, t, 24.0 + 2 * ph, 4.0, 1800, 0.5, step)
            scaled("upsOutputCurrent", i, 10, ph)
            p = rint(v * i * 0.95)
            add("upsOutputPower", p, float(p), ph)
            pl = rint(100.0 * p / 10000.0)
            add("upsOutputPercentLoad", pl, float(pl), ph)
        add("upsAlarmsPresent", 0, 0)
        return V

    def trap_varbinds(self, step):
        vs = {v.obj.name: v for v in self.sample(step)}
        return [
            (vs["upsEstimatedMinutesRemaining"].oid, "Integer",
             vs["upsEstimatedMinutesRemaining"].raw),
            (vs["upsSecondsOnBattery"].oid, "Integer", 0),
            (UPS_CONFIG_LOW_BATT_TIME, "Integer", 2),
        ]
