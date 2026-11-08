# SPDX-License-Identifier: GPL-3.0-or-later
"""Vertiv Liebert CRAC unit (LIEBERT-GP-ENVIRONMENTAL-MIB / -CONDITIONS-MIB,
enterprise 476.1.42).

Temperature/humidity tables carry both the whole-degree column and the
...Tenths... column, like the real Liebert IntelliSlot cards. Setpoints are
writable and move the controlled temperatures. A periodic "hot excursion"
raises a lgpConditionHighTemperature row in the conditions table.
"""

from simcore import Model, Obj, Var, wave, rint, check_int, TWO32

ENV = "LIEBERT-GP-ENVIRONMENTAL-MIB"
CND = "LIEBERT-GP-CONDITIONS-MIB"
L = "1.3.6.1.4.1.476.1.42.3"
E = L + ".4"

ONOFF = {1: "on", 2: "off"}
SYS_STATE = {1: "on", 2: "off", 3: "standby"}
COND_TYPE = {0: "not-specified", 2: "message", 4: "warning", 6: "alarm", 8: "fault"}
COND_STATE = {1: "active", 2: "inactive"}
COND_SEV = {0: "not-applicable", 3: "minor", 6: "major", 9: "critical"}
ACK = {1: "notAcknowledged", 2: "acknowledged"}

O = {}


def o(mib, name, oid, typ, units=None, enum=None, **kw):
    O[name] = Obj(mib, name, oid, typ, units=units, enum=enum, **kw)
    return O[name]


o(ENV, "lgpEnvTemperatureSettingDegC", E + ".1.3.1", "Integer", "degC",
  writable=True, check=check_int(10, 35))
o(ENV, "lgpEnvTemperatureToleranceDegC", E + ".1.3.2", "Integer", "degC")
o(ENV, "lgpEnvTemperatureIdDegC", E + ".1.3.3.1.1", "Gauge32")
o(ENV, "lgpEnvTemperatureDescrDegC", E + ".1.3.3.1.2", "OID")
o(ENV, "lgpEnvTemperatureMeasurementDegC", E + ".1.3.3.1.3", "Integer", "degC")
o(ENV, "lgpEnvTemperatureHighThresholdDegC", E + ".1.3.3.1.4", "Integer", "degC")
o(ENV, "lgpEnvTemperatureLowThresholdDegC", E + ".1.3.3.1.5", "Integer", "degC")
o(ENV, "lgpEnvTemperatureMeasurementTenthsDegC", E + ".1.3.3.1.50", "Integer", "degC")
o(ENV, "lgpEnvHumiditySettingRel", E + ".2.2.1", "Integer", "%RH",
  writable=True, check=check_int(20, 80))
o(ENV, "lgpEnvHumidityToleranceRel", E + ".2.2.2", "Integer", "%RH")
o(ENV, "lgpEnvHumidityIdRel", E + ".2.2.3.1.1", "Gauge32")
o(ENV, "lgpEnvHumidityDescrRel", E + ".2.2.3.1.2", "OID")
o(ENV, "lgpEnvHumidityMeasurementRel", E + ".2.2.3.1.3", "Integer", "%RH")
o(ENV, "lgpEnvHumidityMeasurementRelTenths", E + ".2.2.3.1.50", "Integer", "%RH")
o(ENV, "lgpEnvStateSystem", E + ".3.1", "Integer", enum=SYS_STATE)
o(ENV, "lgpEnvStateCooling", E + ".3.2", "Integer", enum=ONOFF)
o(ENV, "lgpEnvStateHeating", E + ".3.3", "Integer", enum=ONOFF)
o(ENV, "lgpEnvStateHumidifying", E + ".3.4", "Integer", enum=ONOFF)
o(ENV, "lgpEnvStateDehumidifying", E + ".3.5", "Integer", enum=ONOFF)
o(ENV, "lgpEnvStateFan", E + ".3.7", "Integer", enum=ONOFF)
o(ENV, "lgpEnvStateGeneralAlarmOutput", E + ".3.8", "Integer", enum=ONOFF)
o(ENV, "lgpEnvStateCoolingCapacity", E + ".3.9", "Gauge32", "%")
o(CND, "lgpConditionsPresent", L + ".2.2", "Gauge32")
o(CND, "lgpConditionId", L + ".2.3.1.1", "Gauge32")
o(CND, "lgpConditionDescr", L + ".2.3.1.2", "OID")
o(CND, "lgpConditionTime", L + ".2.3.1.3", "TimeTicks", "s")
o(CND, "lgpConditionType", L + ".2.3.1.10", "Integer", enum=COND_TYPE)
o(CND, "lgpConditionCurrentState", L + ".2.3.1.12", "Integer", enum=COND_STATE)
o(CND, "lgpConditionSeverity", L + ".2.3.1.14", "Integer", enum=COND_SEV)
o(CND, "lgpConditionAcknowledged", L + ".2.3.1.18", "Integer", enum=ACK)

# OBJECT-IDENTITY values used as row descriptors, and the notification
REF_OBJECTS = [
    Obj(ENV, "lgpEnvControlTemperature", E + ".1.1.1", "OID"),
    Obj(ENV, "lgpEnvReturnAirTemperature", E + ".1.1.2", "OID"),
    Obj(ENV, "lgpEnvSupplyAirTemperature", E + ".1.1.3", "OID"),
    Obj(ENV, "lgpEnvControlHumidity", E + ".2.1.1", "OID"),
    Obj(ENV, "lgpEnvReturnAirHumidity", E + ".2.1.2", "OID"),
    Obj(CND, "lgpConditionHighTemperature", L + ".2.1.1", "OID"),
    Obj(CND, "lgpConditionChangeFilter", L + ".2.1.6", "OID"),
    Obj("LIEBERT-GP-NOTIFICATIONS-MIB", "lgpEventConditionEntryAdded",
        L + ".3.0.1", "OID"),
    Obj("LIEBERT-GP-REGISTRATION-MIB", "liebertGlobalProducts", "1.3.6.1.4.1.476.1.42", "OID"),
]
REF = {x.name: x.oid for x in REF_OBJECTS}

EXCURSION_PERIOD = 1200.0   # s
EXCURSION_LEN = 240.0       # s


class LiebertCrac(Model):
    name = "liebert-crac"
    sysObjectID = "1.3.6.1.4.1.476.1.42"
    sysDescr = "Liebert DS; Vertiv IntelliSlot Unity Card RDU101 v8.2.0.0_00125"
    sysName = "crac-03"
    contact = "facilities@example.com"
    location = "DC1 Hall 2 CRAC-03"
    objects = list(O.values())
    ref_objects = REF_OBJECTS
    pass_roots = ["1.3.6.1.4.1.476.1.42.3"]
    trap_oid = REF["lgpEventConditionEntryAdded"]

    def setpoints(self):
        sp = int(self.state.get(O["lgpEnvTemperatureSettingDegC"].oid + ".0", "22"))
        hsp = int(self.state.get(O["lgpEnvHumiditySettingRel"].oid + ".0", "45"))
        return sp, hsp

    def conditions(self, t):
        """-> list of (id, descr_oid, start_t, type, severity)."""
        conds = [(1, REF["lgpConditionChangeFilter"], 3600.0, 4, 3)]
        cyc = t % EXCURSION_PERIOD
        if cyc < EXCURSION_LEN:
            start = t - cyc
            conds.append((2 + int(t // EXCURSION_PERIOD) % 1000, REF["lgpConditionHighTemperature"],
                          start, 6, 6))
        return conds

    def sample(self, step):
        t = self.t_of(step)
        sp, hsp = self.setpoints()
        V = []

        def add(name, idx, raw, eng=None):
            V.append(Var(O[name], idx, raw, eng))

        cyc = t % EXCURSION_PERIOD
        hot = 5.5 * max(0.0, 1.0 - abs(cyc - EXCURSION_LEN / 2) / (EXCURSION_LEN / 2)) \
            if cyc < EXCURSION_LEN else 0.0
        ret = wave("ret", t, sp + 0.8, 0.9, 1500, 0.1, step) + hot
        sup = wave("sup", t, sp - 7.5, 0.6, 1100, 0.1, step) + hot * 0.4
        temps = {1: ret, 2: ret, 3: sup}
        hum = wave("hum", t, hsp + 1.0, 2.5, 3000, 0.3, step)

        add("lgpEnvTemperatureSettingDegC", 0, sp, float(sp))
        add("lgpEnvTemperatureToleranceDegC", 0, 10, 1.0)  # UNITS "0.1 degrees Celsius"
        descr = {1: "lgpEnvControlTemperature", 2: "lgpEnvReturnAirTemperature",
                 3: "lgpEnvSupplyAirTemperature"}
        for i in (1, 2, 3):
            add("lgpEnvTemperatureIdDegC", i, i)
            add("lgpEnvTemperatureDescrDegC", i, REF[descr[i]])
            whole = rint(temps[i])
            add("lgpEnvTemperatureMeasurementDegC", i, whole, float(whole))
            hi, lo = (sp + 4, sp - 4) if i != 3 else (sp - 3, sp - 12)
            add("lgpEnvTemperatureHighThresholdDegC", i, hi, float(hi))
            add("lgpEnvTemperatureLowThresholdDegC", i, lo, float(lo))
            tt = rint(temps[i] * 10)
            add("lgpEnvTemperatureMeasurementTenthsDegC", i, tt, tt / 10.0)
        add("lgpEnvHumiditySettingRel", 0, hsp, float(hsp))
        add("lgpEnvHumidityToleranceRel", 0, 5, 5.0)
        hdescr = {1: "lgpEnvControlHumidity", 2: "lgpEnvReturnAirHumidity"}
        for i in (1, 2):
            add("lgpEnvHumidityIdRel", i, i)
            add("lgpEnvHumidityDescrRel", i, REF[hdescr[i]])
            hw = rint(hum)
            add("lgpEnvHumidityMeasurementRel", i, hw, float(hw))
            ht = rint(hum * 10)
            add("lgpEnvHumidityMeasurementRelTenths", i, ht, ht / 10.0)

        cap = max(0, min(100, rint(55 + 9 * (ret - sp) + 2 * hot)))
        conds = self.conditions(t)
        alarm = any(c[3] >= 6 for c in conds)
        add("lgpEnvStateSystem", 0, 1, 1)
        add("lgpEnvStateCooling", 0, 1 if cap > 0 else 2, 1 if cap > 0 else 2)
        add("lgpEnvStateHeating", 0, 2, 2)
        hm = 1 if hum < hsp - 3 else 2
        add("lgpEnvStateHumidifying", 0, hm, hm)
        dh = 1 if hum > hsp + 3 else 2
        add("lgpEnvStateDehumidifying", 0, dh, dh)
        add("lgpEnvStateFan", 0, 1, 1)
        add("lgpEnvStateGeneralAlarmOutput", 0, 1 if alarm else 2, 1 if alarm else 2)
        add("lgpEnvStateCoolingCapacity", 0, cap, float(cap))

        add("lgpConditionsPresent", 0, len(conds), len(conds))
        for cid, d, start, typ, sev in conds:
            add("lgpConditionId", cid, cid)
            add("lgpConditionDescr", cid, d)
            ticks = rint(start * 100) % TWO32
            add("lgpConditionTime", cid, ticks, ticks / 100.0)
            add("lgpConditionType", cid, typ, typ)
            add("lgpConditionCurrentState", cid, 1, 1)
            add("lgpConditionSeverity", cid, sev, sev)
            add("lgpConditionAcknowledged", cid, 1, 1)
        return V

    def trap_varbinds(self, step):
        t = self.t_of(step)
        conds = self.conditions(t)
        cid, d, start, _typ, _sev = conds[-1]
        return [
            (O["lgpConditionId"].oid + ".%d" % cid, "Gauge32", cid),
            (O["lgpConditionDescr"].oid + ".%d" % cid, "OID", d),
            (O["lgpConditionTime"].oid + ".%d" % cid, "TimeTicks", rint(start * 100) % TWO32),
        ]
