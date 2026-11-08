# SPDX-License-Identifier: GPL-3.0-or-later
"""APC Smart-UPS with a Network Management Card (PowerNet-MIB, enterprise 318).

OIDs verified against PowerNet-MIB (see sims/README.md, tools/verify-oids.py).
Scaling as the real NMC: upsAdv* are whole units, upsHighPrec* are tenths.
"""

from simcore import Model, Obj, Var, wave, noise, rint

M = "PowerNet-MIB"
B = "1.3.6.1.4.1.318.1.1.1"

BATT_STATUS = {1: "unknown", 2: "batteryNormal", 3: "batteryLow",
               4: "batteryInFaultCondition"}
REPLACE = {1: "noBatteryNeedsReplacing", 2: "batteryNeedsReplacing"}
OUT_STATUS = {1: "unknown", 2: "onLine", 3: "onBattery", 4: "onSmartBoost",
              5: "timedSleeping", 6: "softwareBypass", 7: "off", 8: "rebooting",
              9: "switchedBypass", 10: "hardwareFailureBypass", 11: "sleepingUntilPowerReturn",
              12: "onSmartTrim", 13: "ecoMode", 14: "hotStandby", 15: "onBatteryTest",
              16: "emergencyStaticBypass", 17: "staticBypassStandby",
              18: "powerSavingMode", 19: "spotMode", 20: "eConversion",
              21: "chargerSpotmode", 22: "inverterSpotmode", 23: "activeLoad",
              24: "batteryDischargeSpotmode", 25: "inverterStandby",
              26: "chargerOnly", 27: "distributedEnergyReserve", 28: "selfTest"}

O = {}


def o(name, sub, typ, units=None, enum=None):
    O[name] = Obj(M, name, "%s.%s" % (B, sub), typ, units=units, enum=enum)
    return O[name]


o("upsBasicIdentModel", "1.1.1", "OctetString")
o("upsBasicIdentName", "1.1.2", "OctetString")
o("upsAdvIdentFirmwareRevision", "1.2.1", "OctetString")
o("upsAdvIdentDateOfManufacture", "1.2.2", "OctetString")
o("upsAdvIdentSerialNumber", "1.2.3", "OctetString")
o("upsBasicBatteryStatus", "2.1.1", "Integer", enum=BATT_STATUS)
o("upsBasicBatteryTimeOnBattery", "2.1.2", "TimeTicks", "s")
o("upsAdvBatteryCapacity", "2.2.1", "Gauge32", "%")
o("upsAdvBatteryTemperature", "2.2.2", "Gauge32", "degC")
o("upsAdvBatteryRunTimeRemaining", "2.2.3", "TimeTicks", "s")
o("upsAdvBatteryReplaceIndicator", "2.2.4", "Integer", enum=REPLACE)
o("upsAdvBatteryNominalVoltage", "2.2.7", "Integer", "V")
o("upsAdvBatteryActualVoltage", "2.2.8", "Integer", "V")
o("upsHighPrecBatteryCapacity", "2.3.1", "Gauge32", "%")
o("upsHighPrecBatteryTemperature", "2.3.2", "Gauge32", "degC")
o("upsHighPrecBatteryNominalVoltage", "2.3.3", "Integer", "V")
o("upsHighPrecBatteryActualVoltage", "2.3.4", "Integer", "V")
o("upsAdvInputLineVoltage", "3.2.1", "Gauge32", "V")
o("upsAdvInputFrequency", "3.2.4", "Gauge32", "Hz")
o("upsHighPrecInputLineVoltage", "3.3.1", "Gauge32", "V")
o("upsHighPrecInputFrequency", "3.3.4", "Gauge32", "Hz")
o("upsBasicOutputStatus", "4.1.1", "Integer", enum=OUT_STATUS)
o("upsAdvOutputVoltage", "4.2.1", "Gauge32", "V")
o("upsAdvOutputFrequency", "4.2.2", "Gauge32", "Hz")
o("upsAdvOutputLoad", "4.2.3", "Gauge32", "%")
o("upsAdvOutputCurrent", "4.2.4", "Gauge32", "A")
o("upsHighPrecOutputVoltage", "4.3.1", "Gauge32", "V")
o("upsHighPrecOutputFrequency", "4.3.2", "Gauge32", "Hz")
o("upsHighPrecOutputLoad", "4.3.3", "Gauge32", "%")
o("upsHighPrecOutputCurrent", "4.3.4", "Gauge32", "A")

MTRAP_STRING = "1.3.6.1.4.1.318.2.3.3.0"   # PowerNet-MIB::mtrapargsString.0
UPS_ON_BATTERY = "1.3.6.1.4.1.318.0.5"     # PowerNet-MIB::upsOnBattery (TRAP-TYPE 5)
REF_OBJECTS = [
    Obj(M, "smartUPS3000", "1.3.6.1.4.1.318.1.3.2.12", "OID"),
    Obj(M, "mtrapargsString", "1.3.6.1.4.1.318.2.3.3", "OctetString"),
    # SMIv1 TRAP-TYPE upsOnBattery ENTERPRISE apc ::= 5  ->  v2 OID apc.0.5
    Obj(M, "apc", "1.3.6.1.4.1.318", "OID"),
]


class ApcUps(Model):
    name = "apc-smart-ups"
    sysObjectID = "1.3.6.1.4.1.318.1.3.2.12"   # PowerNet-MIB::smartUPS3000
    sysDescr = ("APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 "
                "PN:apc_hw05_aos_696.bin AF1:v6.9.6 AN1:apc_hw05_sumx_696.bin "
                "MN:AP9631 HR:05 SN: ZA1752012345 MD:12/22/2017)")
    sysName = "ups-a1"
    contact = "facilities@example.com"
    location = "DC1 Row A Rack 1"
    objects = list(O.values())
    ref_objects = REF_OBJECTS
    pass_roots = ["1.3.6.1.4.1.318.1.1.1"]
    trap_oid = UPS_ON_BATTERY

    def phys(self, step):
        t = self.t_of(step)
        # an outage window of ~3 minutes every 30 minutes: on battery
        cyc = t % 1800.0
        on_batt = 600.0 <= cyc < 780.0
        load = wave("load", t, 38.0, 9.0, 3600, 0.6, step)          # %
        temp = wave("btemp", t, 26.0, 2.5, 7200, 0.15, step)       # degC
        vin = 0.0 if on_batt else wave("vin", t, 120.5, 2.0, 900, 0.4, step)
        fin = 0.0 if on_batt else wave("fin", t, 60.0, 0.05, 300, 0.02, step)
        if on_batt:
            cap = 100.0 - (cyc - 600.0) / 180.0 * 12.0
            tob = cyc - 600.0
        else:
            cap = min(100.0, 88.0 + (cyc - 780.0) / 60.0) if cyc >= 780.0 else 100.0
            tob = 0.0
        vbat = 13.4 * 4 * (0.93 + 0.07 * cap / 100.0) + 0.05 * noise("vbat", step)
        vout = wave("vout", t, 120.0, 0.6, 600, 0.2, step)
        fout = 60.0 if on_batt else fin
        iout = 3000 * 0.9 * load / 100.0 / vout
        runtime_min = max(1.0, 95.0 * (cap / 100.0) * (35.0 / max(load, 5.0)))
        return dict(on_batt=on_batt, load=load, temp=temp, vin=vin, fin=fin, cap=cap,
                    tob=tob, vbat=vbat, vout=vout, fout=fout, iout=iout,
                    runtime=runtime_min * 60.0)

    def sample(self, step):
        p = self.phys(step)
        V = []

        def add(name, raw, eng=None):
            V.append(Var(O[name], 0, raw, eng))

        def tenths(name, x):
            r = rint(x * 10)
            add(name, r, r / 10.0)

        def whole(name, x):
            r = rint(x)
            add(name, r, float(r))

        add("upsBasicIdentModel", "Smart-UPS 3000")
        add("upsBasicIdentName", "UPS_IDEN")
        add("upsAdvIdentFirmwareRevision", "UPS 09.3 / ID=18")
        add("upsAdvIdentDateOfManufacture", "06/14/2017")
        add("upsAdvIdentSerialNumber", "AS1724123456")
        bst = 3 if p["cap"] < 90 and p["on_batt"] else 2
        add("upsBasicBatteryStatus", bst, bst)
        tob = rint(p["tob"] * 100)
        add("upsBasicBatteryTimeOnBattery", tob, tob / 100.0)
        whole("upsAdvBatteryCapacity", p["cap"])
        whole("upsAdvBatteryTemperature", p["temp"])
        rt = rint(p["runtime"]) * 100
        add("upsAdvBatteryRunTimeRemaining", rt, rt / 100.0)
        add("upsAdvBatteryReplaceIndicator", 1, 1)
        add("upsAdvBatteryNominalVoltage", 48, 48.0)
        whole("upsAdvBatteryActualVoltage", p["vbat"])
        tenths("upsHighPrecBatteryCapacity", p["cap"])
        tenths("upsHighPrecBatteryTemperature", p["temp"])
        add("upsHighPrecBatteryNominalVoltage", 480, 48.0)
        tenths("upsHighPrecBatteryActualVoltage", p["vbat"])
        whole("upsAdvInputLineVoltage", p["vin"])
        whole("upsAdvInputFrequency", p["fin"])
        tenths("upsHighPrecInputLineVoltage", p["vin"])
        tenths("upsHighPrecInputFrequency", p["fin"])
        st = 3 if p["on_batt"] else 2
        add("upsBasicOutputStatus", st, st)
        whole("upsAdvOutputVoltage", p["vout"])
        whole("upsAdvOutputFrequency", p["fout"])
        whole("upsAdvOutputLoad", p["load"])
        whole("upsAdvOutputCurrent", p["iout"])
        tenths("upsHighPrecOutputVoltage", p["vout"])
        tenths("upsHighPrecOutputFrequency", p["fout"])
        tenths("upsHighPrecOutputLoad", p["load"])
        tenths("upsHighPrecOutputCurrent", p["iout"])
        return V

    def trap_varbinds(self, step):
        return [(MTRAP_STRING, "OctetString",
                 "UPS: On battery power in response to an input power problem.")]
