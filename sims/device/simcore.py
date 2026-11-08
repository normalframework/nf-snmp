# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared simulator core: deterministic signal generators, object/varbind
model, normalized (docs/internals.md §1) value encoding, persisted write state.

Everything here is stdlib-only so it runs under snmpd's pass_persist with the
distro python3, and under the quirky sim's python image.
"""

import hashlib
import json
import math
import os
import threading

TWO32 = 1 << 32
TWO64 = 1 << 64

# Epoch for "device boot" so counters look like they started counting at a
# fixed point in the past (2025-01-01T00:00:00Z) - deterministic, no state.
BOOT_EPOCH_MS = 1735689600000

TYPES = ("Integer", "OctetString", "OID", "IpAddress", "Counter32", "Gauge32",
         "TimeTicks", "Opaque", "Counter64")


# --------------------------------------------------------------------------
# deterministic signal helpers: all pure functions of (key, step)
# --------------------------------------------------------------------------

def h01(*key):
    """Uniform float in [0, 1) derived from the key - stable across runs."""
    d = hashlib.sha256("|".join(str(k) for k in key).encode()).digest()
    return int.from_bytes(d[:8], "big") / float(TWO64)


def noise(key, step):
    """Uniform noise in [-1, 1) keyed by (key, step)."""
    return 2.0 * h01("n", key, step) - 1.0


def wave(key, t, base, amp, period_s, noise_amp=0.0, step=None):
    """base + amp*sin(2*pi*t/period + phase(key)) + noise_amp*noise(key, step)."""
    phase = 2 * math.pi * h01("phase", key)
    v = base + amp * math.sin(2 * math.pi * t / period_s + phase)
    if noise_amp:
        v += noise_amp * noise(key, step if step is not None else int(t))
    return v


def ramp_counter(key, t, rate, wobble=0.5, period_s=600.0):
    """Monotonic counter = integral of rate*(1 + wobble*sin(2*pi*t/P + ph)).

    Closed form, so it is a pure function of t and never decreases while
    wobble < 1.  Returns a non-negative Python int (arbitrary precision).
    """
    phase = 2 * math.pi * h01("cphase", key)
    w = 2 * math.pi / period_s
    # integral_0^t r*(1 + a sin(w s + ph)) ds = r*t + r*a/w*(cos(ph) - cos(w t + ph))
    v = rate * t + rate * wobble / w * (math.cos(phase) - math.cos(w * t + phase))
    return int(v)


def rint(x):
    """Round half away from zero to int (what a firmware typically does)."""
    return int(math.floor(x + 0.5)) if x >= 0 else -int(math.floor(-x + 0.5))


# --------------------------------------------------------------------------
# MIB object metadata
# --------------------------------------------------------------------------

class Obj:
    """One MIB object (scalar or table column).

    oid is the object OID (no instance suffix). typ is a §1 type name.
    `mib` is the module the name/OID was verified against (tools/verify-oids.py).
    For writable objects, `check(value_str) -> normalized value_str` validates a
    SET (raise WriteError) - value_str is in §1 normalized form.
    """

    def __init__(self, mib, name, oid, typ, units=None, writable=False,
                 enum=None, check=None):
        assert typ in TYPES, typ
        self.mib = mib
        self.name = name
        self.oid = oid
        self.typ = typ
        self.units = units
        self.writable = writable
        self.enum = enum
        self.check = check


class WriteError(Exception):
    """pass_persist error token: not-writable, wrong-type, wrong-length,
    wrong-value, inconsistent-value."""


NULL = object()   # eng sentinel: "no physical value" (emitted as JSON null)


class Var:
    """A sampled instance: object + index suffix + raw + optional eng value."""
    __slots__ = ("obj", "index", "raw", "eng", "units")

    def __init__(self, obj, index, raw, eng=None, units=None):
        self.obj = obj
        self.index = str(index)
        self.raw = raw
        self.eng = eng
        self.units = units if units is not None else obj.units

    @property
    def oid(self):
        return "%s.%s" % (self.obj.oid, self.index)


def str_index(s):
    """Encode a string as an implied-length-prefixed OID index (n.c1.c2...)."""
    b = s.encode()
    return ".".join([str(len(b))] + [str(c) for c in b])


# --------------------------------------------------------------------------
# value normalization (§1)
# --------------------------------------------------------------------------

def norm_value(typ, raw):
    """Python model value -> §1 normalized string."""
    if typ in ("OctetString", "Opaque"):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return bytes(raw).hex()
    if typ in ("OID", "IpAddress"):
        return str(raw).lstrip(".")
    v = int(raw)
    if typ == "Integer":
        assert -(1 << 31) <= v < (1 << 31), (typ, v)
    elif typ == "Counter64":
        v %= TWO64
    elif typ in ("Counter32", "Gauge32", "TimeTicks"):
        assert 0 <= v < TWO32 or typ == "Counter32", (typ, v)
        v %= TWO32
    return str(v)


def oid_key(oid):
    return tuple(int(x) for x in oid.strip(".").split(".") if x != "")


# --------------------------------------------------------------------------
# write state shared between pass_persist and the HTTP server
# --------------------------------------------------------------------------

class StateStore:
    """Tiny JSON file store: {"writes": {instance_oid: {"type","value"}}}.

    Written atomically (tmp + rename); readers re-load when mtime changes, so
    the snmpd pass_persist process and the HTTP server see the same writes.
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._mtime = None
        self._data = {"writes": {}}

    def load(self):
        try:
            st = os.stat(self.path)
            m = (st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            self._mtime = None
            self._data = {"writes": {}}
            return self._data
        if m != self._mtime:
            try:
                with open(self.path) as f:
                    self._data = json.load(f)
                self._mtime = m
            except (OSError, ValueError):
                pass
        return self._data

    def writes(self):
        return self.load().get("writes", {})

    def get(self, oid, default=None):
        w = self.writes().get(oid)
        return w["value"] if w else default

    def put(self, oid, typ, value):
        with self._lock:
            data = json.loads(json.dumps(self.load()))
            data.setdefault("writes", {})[oid] = {"type": typ, "value": value}
            tmp = "%s.%d.tmp" % (self.path, os.getpid())
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
            self._mtime = None

    def reset(self):
        with self._lock:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._mtime = None
            self._data = {"writes": {}}


# --------------------------------------------------------------------------
# write validators
# --------------------------------------------------------------------------

def check_int(lo, hi, allowed=None):
    def chk(v):
        try:
            n = int(v)
        except ValueError:
            raise WriteError("wrong-type")
        if allowed is not None and n not in allowed:
            raise WriteError("wrong-value")
        if not lo <= n <= hi:
            raise WriteError("wrong-value")
        return str(n)
    return chk


def check_str(maxlen=255):
    def chk(hexv):
        if len(hexv) // 2 > maxlen:
            raise WriteError("wrong-length")
        return hexv
    return chk


def str_from_hex(hexv):
    """Stored §1 hex -> str when it is valid UTF-8, else the raw bytes (so
    binary values written via SET round-trip byte-exactly)."""
    b = bytes.fromhex(hexv)
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b


# --------------------------------------------------------------------------
# base model
# --------------------------------------------------------------------------

SYS_CONTACT = Obj("SNMPv2-MIB", "sysContact", "1.3.6.1.2.1.1.4", "OctetString",
                  writable=True, check=check_str(255))
SYS_LOCATION = Obj("SNMPv2-MIB", "sysLocation", "1.3.6.1.2.1.1.6", "OctetString",
                   writable=True, check=check_str(255))


class Model:
    """Subclasses set the class attributes and implement sample()."""
    name = "base"
    sysObjectID = "1.3.6.1.4.1.99999"
    sysDescr = ""
    sysName = ""
    contact = "noc@example.com"
    location = "Lab"
    objects = []           # list[Obj] (excluding the system group)
    pass_roots = []        # subtrees served by pass_persist
    snmpd_exclude = []     # snmpd MIB modules disabled (-I -mod)
    trap = None            # dict: oid, varbinds(step, state) -> [(oid, typ, raw)]

    def __init__(self, state, step_ms=10000):
        self.state = state
        self.step_ms = step_ms

    # -- system group pieces served by pass_persist (writable, persisted) --
    def system_vars(self):
        return [
            Var(SYS_CONTACT, 0, str_from_hex(self.state.get(
                "1.3.6.1.2.1.1.4.0", self.contact.encode().hex())), None),
            Var(SYS_LOCATION, 0, str_from_hex(self.state.get(
                "1.3.6.1.2.1.1.6.0", self.location.encode().hex())), None),
        ]

    def all_objects(self):
        return [SYS_CONTACT, SYS_LOCATION] + list(self.objects)

    def sample(self, step):  # pragma: no cover - abstract
        raise NotImplementedError

    def t_of(self, step):
        """Seconds since the simulated device boot for this step."""
        return (step * self.step_ms - BOOT_EPOCH_MS) / 1000.0

    # -- snapshot --
    def snapshot(self, step):
        """-> (sorted list of (oid_tuple, oid, typ, value_str), eng dict)."""
        vs = self.system_vars() + self.sample(step)
        rows = []
        eng = {}
        for v in vs:
            val = norm_value(v.obj.typ, v.raw)
            rows.append((oid_key(v.oid), v.oid, v.obj.typ, val))
            key = "%s.%s" % (v.obj.name, v.index)
            if v.eng is not None:
                e = {"value": None if v.eng is NULL else v.eng}
                if v.units:
                    e["units"] = v.units
                if v.obj.enum and isinstance(v.raw, int) and v.raw in v.obj.enum:
                    e["enum"] = v.obj.enum[v.raw]
                eng[key] = e
            elif v.obj.typ == "OctetString":
                eng[key] = {"value": v.raw if isinstance(v.raw, str)
                            else bytes(v.raw).hex()}
        rows.sort(key=lambda r: r[0])
        return rows, eng

    def writable_objects(self):
        return [o for o in self.all_objects() if o.writable]

    def validate_write(self, oid, typ, value, step):
        """Check a SET; returns the normalized value to store or raises."""
        rows, _ = self.snapshot(step)
        for _, o, t, _v in rows:
            if o == oid:
                break
        else:
            raise WriteError("not-writable")
        for obj in self.writable_objects():
            if oid.startswith(obj.oid + "."):
                if typ != obj.typ:
                    raise WriteError("wrong-type")
                val = obj.check(value) if obj.check else value
                self.on_write(obj, oid[len(obj.oid) + 1:], val, step)
                return val
        raise WriteError("not-writable")

    def on_write(self, obj, index, value, step):
        """Hook for side effects (e.g. outlet switching timestamps)."""

    def trap_varbinds(self, step):
        return []
