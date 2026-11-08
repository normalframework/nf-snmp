# nf-snmp internals and contracts

This document is the shared contract between modules, simulators and test harnesses.
Change it **before** changing an interface.

Conventions: plain JavaScript, CommonJS, Node ≥ 20 (NF runs Node 22), no build step.
Logging goes through an injected `log` object with `{debug,info,warn,error}(msg, fields?)`.
`lib/**` never imports `@normalframework/applications-sdk`; NF access is via `lib/nf`.
License: GPL-3.0-or-later.

## 0. Layout

```
app.json                 NF app manifest: layer "snmp" with an HTTP driver, polled
hooks/engine.js          scheduled watchdog that starts the engine singleton
lib/snmp/                SNMP client wrapper (net-snmp), normalization, batching, quirks
lib/profiles/            profile loader, matcher, decoder (raw varbind -> engineering value)
lib/engine/              engine, driver HTTP server, point publisher, config store, discovery, traps
lib/nf/                  NF REST adapter (+ fake for tests)
profiles/<vendor>/*.json built-in device profiles
static/                  admin-console iframe UI
bin/nf-snmp.js           CLI: get / walk / bulkwalk / discover / profile-test (also the difftest "ours" client)
sims/                    synthetic SNMP device simulators (docker)
difftest/                reference client implementations + differential harness
test/unit test/difftest test/e2e
```

## 1. Normalized varbind format (used by `lib/snmp`, the CLI and every difftest reference client)

One JSON object per varbind:

```json
{"oid": "1.3.6.1.2.1.1.3.0", "type": "TimeTicks", "value": "123456"}
```

- `oid`: numeric dotted, no leading dot.
- `type`: one of `Integer`, `OctetString`, `OID`, `IpAddress`, `Counter32`, `Gauge32`,
  `TimeTicks`, `Opaque`, `Counter64`, `Null`, `NoSuchObject`, `NoSuchInstance`, `EndOfMibView`.
  (`Unsigned32` is reported as `Gauge32`; they share a tag.)
- `value`: always a string.
  - integer types: base-10 (Counter64 as an exact decimal string, never a float)
  - `OctetString` / `Opaque`: lowercase hex, no separators (`"4170432055505320"`); empty string → `""`
  - `OID`: numeric dotted
  - `IpAddress`: dotted quad
  - `Null` / exceptions: `""`
- Request-level failure: one object `{"error": "<class>", "message": "...", "status"?: "<RFC 3416 error-status name>", "index"?: <1-based error-index>}` where class is one of
  `timeout`, `authError`, `tooBig`, `noSuchName`, `genErr`, `badValue`, `readOnly`, `noAccess`,
  `notWritable`, `wrongType`, `decodeError`, `other`.

Operations (same semantics in every implementation):

| op | input | output |
|---|---|---|
| `get` | list of OIDs, sent as ONE PDU | one varbind per requested OID, in request order (v1 `noSuchName` → request error) |
| `walk` | root OID | GETNEXT walk; stop when the OID leaves the subtree, on endOfMibView, or on a non-increasing OID (then emit `{"error":"nonIncreasing"}` as the last line) |
| `bulkwalk` | root OID, `maxRepetitions` | GETBULK walk, same stop rules. **nf-snmp only:** on `tooBig` it halves max-repetitions and continues (references stop with the error); allowlisted as `ours-bulkwalk-toobig-adaptive` |
| `set` | list of `{oid,type,value}` | the response varbinds |

Target JSON (CLI/harness input):

```json
{"host":"10.0.0.5","port":161,"version":"2c","community":"public",
 "user":"u","authProtocol":"sha256","authKey":"...","privProtocol":"aes","privKey":"...",
 "timeoutMs":2000,"retries":1}
```

`authProtocol` ∈ `none|md5|sha|sha224|sha256|sha384|sha512`; `privProtocol` ∈ `none|des|aes|aes256b|aes256r`.
`version` ∈ `1|2c|3`. v3 security level is implied: no auth → noAuthNoPriv, auth without priv → authNoPriv.

## 2. Simulators (`sims/`)

Each simulated device is a container on the compose network answering SNMP on UDP 161 and a
ground-truth HTTP API on TCP 8000.

**Credentials (every sim):**
- v1/v2c: community `public` (read-only), `private` (read-write).
- v3 users, auth pass `authpass123`, priv pass `privpass123`:
  `noauth` (noAuthNoPriv), `authsha` (SHA/none), `md5des` (MD5/DES), `shaaes` (SHA/AES-128),
  `sha256aes` (SHA-256/AES-128), `sha512aes` (SHA-512/AES-128); and when the agent supports it,
  `sha256aes256` (SHA-256/AES-256 Blumenthal). `GET /info` lists the users actually configured.

**Values are deterministic functions of time** quantized to `stepMs` (default 10000), so the
truth for any timestamp can be recomputed: `value = f(floor(t / stepMs))`.

**HTTP API:**
- `GET /info` → `{"model":"apc-smart-ups","sysObjectID":"1.3.6.1.4.1.318.1.3.2.12","stepMs":10000,"users":[...],"writable":["1.3.6..."]}`
- `GET /truth?at=<unix_ms>` (default now) →
  ```json
  {"at": 1794100000000, "step": 179410000,
   "raw":  {"1.3.6.1.4.1.318.1.1.1.2.3.2.0": {"type":"Gauge32","value":"243"}},
   "eng":  {"upsHighPrecBatteryTemperature.0": {"value": 24.3, "units": "degC"}}}
  ```
  `raw` uses the §1 normalized format (type/value). `eng` is keyed `<MIB object name>.<index>` —
  the physical quantity the sim was modeling, independent of any profile. A profile symbol
  `name` plus the row index must produce the same key, which is how e2e tests check decoding.
- `POST /trap` `{"target":"host:port","version":"2c"|"1"|"3","inform":false,"user":"shaaes"}`
  → sends the model's characteristic trap/notification.
- `POST /set-fault {"kind": "...", ...}` (quirk sim only, see below) and `POST /reset`.
- Writes via SNMP SET to writable OIDs persist in memory and are reflected in `/truth`.

**Device models (one container each):**

| service | model | sysObjectID | notes |
|---|---|---|---|
| `sim-apc-ups` | APC Smart-UPS (PowerNet-MIB) | 1.3.6.1.4.1.318.1.3.2.12 | tenths-of-unit `upsHighPrec*`, battery temp, runtime TimeTicks, enums (upsBasicOutputStatus) |
| `sim-ups-rfc1628` | generic UPS-MIB (RFC 1628) | 1.3.6.1.4.1.99999.1.1 (unknown vendor) | upsInputTable/upsOutputTable rows, 0.1 Hz frequency |
| `sim-raritan-pdu` | Raritan PX (PDU2-MIB) | 1.3.6.1.4.1.13742.6 | inlet/outlet sensor values scaled by `*DecimalDigits`, outlet names, outlet switch (writable) |
| `sim-liebert-crac` | Vertiv Liebert CRAC (LIEBERT-GP) | 1.3.6.1.4.1.476.1.42 | temps/humidity, setpoints (writable), alarms |
| `sim-switch` | switch with ENTITY-SENSOR-MIB + IF-MIB | 1.3.6.1.4.1.9.1.1208 | entPhySensorScale/Precision, ifHCInOctets Counter64 that wraps Counter32 ifInOctets |
| `sim-quirky` | buggy agent (v1/v2c only) | 1.3.6.1.4.1.99998.1 | fault injection, below |

**Quirk sim faults** (env defaults + `/set-fault`): `bulkIgnoresMaxRep` (returns huge responses),
`bulkCrashAboveN` (drops requests with max-repetitions > N), `nonIncreasing` (walk loops at an OID),
`dropRate` (fraction of requests silently dropped), `delayMs`, `tooBigAboveN` (tooBig for PDUs
with more than N varbinds), `counter32Wrap` (fast-incrementing counter that wraps), `floatAsString`
(DisplayString "23.5 C" values), `noSuchInstanceGaps` (holes in a table column).

## 3. Differential testing (`difftest/`)

Reference clients, each a CLI that reads `{target, op, oids|root, maxRepetitions}` JSON on stdin
and writes §1 JSON lines to stdout:

- `ref-netsnmp` — net-snmp C tools (`snmpget/snmpgetnext/snmpbulkwalk/snmpset -On -Ox ...`) with output parsing
- `ref-gosnmp` — small Go program on github.com/gosnmp/gosnmp ≥ v1.47.0
- `ref-pysnmp` — pysnmp (lextudio) hlapi
- `ours` — `node bin/nf-snmp.js op --json` from this repo

They run in the `difftest/` docker image on the same network as the sims. The harness runs a matrix
(sims × versions/users × ops × OID sets), normalizes and diffs. Known, documented divergences are
listed in `difftest/allowlist.json` with a reason; anything else fails the run.

## 4. Profiles (`profiles/<vendor>/<model>.json`)

```json
{
  "id": "apc/smart-ups",
  "name": "APC Smart-UPS",
  "vendor": "APC",
  "extends": ["_base/system"],
  "match": [{"sysObjectID": "1.3.6.1.4.1.318.1.3.2"}, {"sysDescr": "/APC Web/SNMP Management Card/"}],
  "equipType": "ups",
  "defaults": {"periodSeconds": 60},
  "symbols": [
    {"name": "upsHighPrecBatteryTemperature", "oid": "1.3.6.1.4.1.318.1.1.1.2.3.2.0",
     "scale": 0.1, "units": "degC", "class": "battery-temp-sensor"},
    {"name": "upsBasicOutputStatus", "oid": "1.3.6.1.4.1.318.1.1.1.4.1.1.0",
     "enum": {"2": "onLine", "3": "onBattery"}}
  ],
  "tables": [
    {"name": "outlet", "indexOid": "1.3.6.1.4.1.13742.6.3.5.3.1.2",
     "label": {"column": "outletName"},
     "columns": [
       {"name": "outletName", "oid": "1.3.6.1.4.1.13742.6.3.5.3.1.3", "type": "string", "point": false},
       {"name": "measurementsOutletSensorValue", "oid": "...", "decimalDigitsOid": "...", "units": "A"}
     ]}
  ]
}
```

Symbol/column fields: `oid`; `scale` (multiply); `offset` (add after scale); `decimalDigitsOid`
(divide by 10^value read from that OID, same row index for columns); `displayHint` (`d-N`);
`entitySensor` (RFC 3433 decoding using sibling type/scale/precision columns); `enum`;
`regex` (extract a number from an OctetString, first capture group); `type` (`auto|number|string|counter`);
`units`; `class` (NF point class hint); `writable`; `point` (false = helper only, not published);
`sentinels` (raw values meaning "not available").

Match precedence: longest `sysObjectID` prefix match (100/arc, +50 for exact), then `sysDescr` regex
(+50), then `probe` (+10, the OID or any row under it exists), plus the profile's `priority`
(hand-written generics 1..5, imported −5). `sysObjectID` may contain `*` wildcards (Datadog style,
scored by the fixed arcs before the first `*`); a wildcard that does not fix the enterprise number
scores 1 (catch-all). Generic fallbacks live in `profiles/_generic/`.

Other profile keys: `source` (provenance of imported profiles), `verification` (verify summary),
`description`; symbol keys `mib` (module for verification) and `mibVerified: false` (MIB unavailable).

At sync, objects the device answers noSuch* for are dropped (warning), and text-valued symbols become
attributes of the device point (NF trends numbers only).

## 5. NF integration

- Layer `snmp` (app.json): `driver.url.{read,write,status}` → `http://127.0.0.1:47081/driver/*`,
  `polled: true`, indexed. NF's poll service (src/poll) schedules reads for every point with
  `period > 0`, grouped by `parentUuid`, rate-limited per `device_address`.
- Device UUID: uuidv5(`<host>:<port>`, NS) unless given. Point UUID: uuidv5(`<deviceUuid>/<instance oid>`, NS).
- Point attrs on layer `snmp`: `device` (device name), `device_address` (`SNMP:<host>:<port>`),
  `device_uuid`, `profile`, `oid`, `symbol` (`<name>` or `<name>.<label>`), `index`, `units`.
- The engine keeps its own uuid → read spec map (from profile + device config), persisted under
  `local/`. Driver Read requests are served from that map; a point the engine doesn't know falls
  back to the `oid` attribute with auto decoding.
- Writes go through the NF command service → `POST /driver/write` → SNMP SET (only `writable` symbols).
