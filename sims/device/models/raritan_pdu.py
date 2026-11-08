# SPDX-License-Identifier: GPL-3.0-or-later
"""Raritan PX2/PX3 rack PDU (PDU2-MIB, enterprise 13742.6).

Sensor readings are Unsigned32 that must be divided by 10^DecimalDigits read
from the matching *SensorConfigurationTable row (same pduId.xId.sensorType
index) - exactly like the real firmware. Outlet names are writable strings,
outlets are switchable via switchingOperation (off/on/cycle).
"""

from simcore import (Model, Obj, Var, WriteError, wave, rint, ramp_counter,
                     check_str, str_from_hex, BOOT_EPOCH_MS)

M = "PDU2-MIB"
R = "1.3.6.1.4.1.13742.6"

TRUTH = {1: "true", 2: "false"}
SENSOR_STATE = {-1: "unavailable", 0: "open", 1: "closed", 2: "belowLowerCritical",
                3: "belowLowerWarning", 4: "normal", 5: "aboveUpperWarning",
                6: "aboveUpperCritical", 7: "on", 8: "off"}
UNITS = {-1: "none", 1: "volt", 2: "amp", 3: "watt", 4: "voltamp", 5: "wattHour",
         8: "hertz"}
SWITCH_OP = {0: "off", 1: "on", 2: "cycle"}

O = {}


def o(name, oid, typ, units=None, enum=None, **kw):
    O[name] = Obj(M, name, oid, typ, units=units, enum=enum, **kw)
    return O[name]


def _check_switch(v):
    try:
        n = int(v)
    except ValueError:
        raise WriteError("wrong-type")
    if n not in SWITCH_OP:
        raise WriteError("wrong-value")
    # cycle ends with the outlet on; the object reads back the resulting state
    return "1" if n == 2 else str(n)


o("pduManufacturer", R + ".3.2.1.1.2", "OctetString")
o("pduModel", R + ".3.2.1.1.3", "OctetString")
o("pduSerialNumber", R + ".3.2.1.1.4", "OctetString")
o("inletCount", R + ".3.2.2.1.2", "Integer")
o("outletCount", R + ".3.2.2.1.4", "Integer")
o("pduName", R + ".3.2.2.1.13", "OctetString")
o("inletSensorUnits", R + ".3.3.4.1.6", "Integer", enum=UNITS)
o("inletSensorDecimalDigits", R + ".3.3.4.1.7", "Gauge32")
o("outletLabel", R + ".3.5.3.1.2", "OctetString")
o("outletName", R + ".3.5.3.1.3", "OctetString", writable=True, check=check_str(255))
o("outletSensorUnits", R + ".3.5.4.1.6", "Integer", enum=UNITS)
o("outletSensorDecimalDigits", R + ".3.5.4.1.7", "Gauge32")
o("switchingOperation", R + ".4.1.2.1.2", "Integer", enum=SWITCH_OP, writable=True,
  check=_check_switch)
o("outletSwitchingState", R + ".4.1.2.1.3", "Integer", enum=SENSOR_STATE)
o("outletSwitchingTimeStamp", R + ".4.1.2.1.4", "Gauge32", "s")
o("measurementsInletSensorIsAvailable", R + ".5.2.3.1.2", "Integer", enum=TRUTH)
o("measurementsInletSensorState", R + ".5.2.3.1.3", "Integer", enum=SENSOR_STATE)
o("measurementsInletSensorValue", R + ".5.2.3.1.4", "Gauge32")
o("measurementsOutletSensorIsAvailable", R + ".5.4.3.1.2", "Integer", enum=TRUTH)
o("measurementsOutletSensorState", R + ".5.4.3.1.3", "Integer", enum=SENSOR_STATE)
o("measurementsOutletSensorValue", R + ".5.4.3.1.4", "Gauge32")

# notification and its accessible-for-notify objects
REF_OBJECTS = [
    Obj(M, "outletSensorStateChange", R + ".0.63", "OID"),
    Obj(M, "typeOfSensor", R + ".0.0.10", "Integer"),
    Obj(M, "oldSensorState", R + ".0.0.2", "Integer"),
]

# sensorType -> (decimalDigits, unitsEnum, eng units)
INLET_SENSORS = {1: (3, 2, "A"), 4: (0, 1, "V"), 5: (0, 3, "W"), 6: (0, 4, "VA"),
                 7: (2, -1, None), 8: (0, 5, "Wh"), 23: (1, 8, "Hz")}
OUTLET_SENSORS = {1: (3, 2, "A"), 4: (0, 1, "V"), 5: (0, 3, "W"), 7: (2, -1, None),
                  14: (0, -1, None)}
OUTLET_NAMES = ["web-01", "web-02", "db-primary", "db-replica",
                "switch-a", "switch-b", "kvm", ""]
DEFAULT_OFF = {8}


class RaritanPdu(Model):
    name = "raritan-px2"
    sysObjectID = R
    sysDescr = "PX2 3.5.0.5-46025 (Raritan Dominion PX2-5145R)"
    sysName = "pdu-a1-l"
    contact = "facilities@example.com"
    location = "DC1 Row A Rack 1 left"
    objects = list(O.values())
    ref_objects = REF_OBJECTS
    pass_roots = [R]
    trap_oid = R + ".0.63"

    def outlet_on(self, n):
        default = "0" if n in DEFAULT_OFF else "1"
        return self.state.get("%s.1.%d" % (O["switchingOperation"].oid, n), default) != "0"

    def outlet_ts(self, n):
        ts = self.state.get("meta:switchts.%d" % n)
        return int(ts) if ts else BOOT_EPOCH_MS // 1000

    def on_write(self, obj, index, value, step):
        if obj.name == "switchingOperation":
            n = int(index.split(".")[1])
            self.state.put("meta:switchts.%d" % n, "Gauge32",
                           str(step * self.step_ms // 1000))

    def sample(self, step):
        t = self.t_of(step)
        V = []

        def add(name, idx, raw, eng=None, units=None):
            V.append(Var(O[name], idx, raw, eng, units))

        add("pduManufacturer", 1, "Raritan")
        add("pduModel", 1, "PX2-5145R")
        add("pduSerialNumber", 1, "PKE0954001")
        add("inletCount", 1, 1, 1)
        add("outletCount", 1, len(OUTLET_NAMES), len(OUTLET_NAMES))
        add("pduName", 1, "pdu-a1-l")

        vin = wave("vin", t, 208.0, 2.5, 900, 0.6, step)
        freq = wave("freq", t, 60.0, 0.03, 300, 0.02, step)
        outs = {}
        for n in range(1, len(OUTLET_NAMES) + 1):
            on = self.outlet_on(n)
            amps = wave("oa%d" % n, t, 0.4 + 0.25 * n, 0.15 + 0.03 * n, 1200 + 60 * n,
                        0.02, step) if on else 0.0
            pf = wave("pf%d" % n, t, 0.93, 0.03, 2400, 0.005, step) if on else 0.0
            outs[n] = dict(on=on, amps=max(0.0, amps), pf=pf, volts=vin,
                           watts=vin * max(0.0, amps) * pf)
        i_in = sum(x["amps"] for x in outs.values())
        p_in = sum(x["watts"] for x in outs.values())
        va_in = vin * i_in
        pf_in = p_in / va_in if va_in else 0.0
        energy = 18_000_000 + ramp_counter("energy", max(t, 0.0), 1900.0 / 3600.0)
        inlet_phys = {1: i_in, 4: vin, 5: p_in, 6: va_in, 7: pf_in, 8: energy, 23: freq}

        for st, (dd, un, eu) in sorted(INLET_SENSORS.items()):
            idx = "1.1.%d" % st
            add("inletSensorUnits", idx, un, un)
            add("inletSensorDecimalDigits", idx, dd, dd)
            add("measurementsInletSensorIsAvailable", idx, 1, 1)
            add("measurementsInletSensorState", idx, 4, 4)
            raw = rint(inlet_phys[st] * 10 ** dd)
            add("measurementsInletSensorValue", idx, raw, raw / 10.0 ** dd, eu)

        for n, nm in enumerate(OUTLET_NAMES, start=1):
            add("outletLabel", "1.%d" % n, str(n))
            name = str_from_hex(self.state.get("%s.1.%d" % (O["outletName"].oid, n),
                                               nm.encode().hex()))
            add("outletName", "1.%d" % n, name)
        for n, x in outs.items():
            phys = {1: x["amps"], 4: x["volts"], 5: x["watts"], 7: x["pf"]}
            for st, (dd, un, eu) in sorted(OUTLET_SENSORS.items()):
                idx = "1.%d.%d" % (n, st)
                add("outletSensorUnits", idx, un, un)
                add("outletSensorDecimalDigits", idx, dd, dd)
                add("measurementsOutletSensorIsAvailable", idx, 1, 1)
                if st == 14:   # onOff: state only, no numeric reading (like the real PDU)
                    s = 7 if x["on"] else 8
                    add("measurementsOutletSensorState", idx, s, s)
                    continue
                add("measurementsOutletSensorState", idx, 4, 4)
                raw = rint(phys[st] * 10 ** dd)
                add("measurementsOutletSensorValue", idx, raw, raw / 10.0 ** dd, eu)
        for n, x in outs.items():
            idx = "1.%d" % n
            v = 1 if x["on"] else 0
            add("switchingOperation", idx, v, v)
            s = 7 if x["on"] else 8
            add("outletSwitchingState", idx, s, s)
            ts = self.outlet_ts(n)
            add("outletSwitchingTimeStamp", idx, ts, ts)
        return V

    def trap_varbinds(self, step):
        on = self.outlet_on(1)
        return [
            (O["pduName"].oid + ".1", "OctetString", "pdu-a1-l"),
            (O["outletLabel"].oid + ".1.1", "OctetString", "1"),
            (REF_OBJECTS[1].oid + ".0", "Integer", 14),
            (O["measurementsOutletSensorState"].oid + ".1.1.14", "Integer", 7 if on else 8),
            (REF_OBJECTS[2].oid + ".0", "Integer", 8 if on else 7),
        ]
