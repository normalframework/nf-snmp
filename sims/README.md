# nf-snmp simulators

Synthetic SNMP devices for e2e and differential testing of nf-snmp. They do not share
any code with our client. The contract they implement is
[`docs/internals.md` §1–§2](../docs/internals.md).

- **Device sims** (`sim-apc-ups`, `sim-ups-rfc1628`, `sim-raritan-pdu`, `sim-liebert-crac`,
  `sim-switch`) run the **real net-snmp C agent** (`snmpd` 5.9.3 from Debian bookworm). The
  vendor subtrees come from a `pass_persist` script (Python 3, stdlib only) that serves a
  model module. This means PDU encoding, USM/v3, GETBULK, error mapping and v1/v2c
  semantics all come from a real-world agent. All five use one image (`nfsnmp-sim-device`),
  and `SIM_MODEL` picks the model.
- **`sim-quirky`** is a deliberately buggy v1/v2c agent built on the pysnmp (lextudio,
  pinned 7.1.22) low-level proto API and pyasn1. It injects faults at the PDU level.

## Running

```sh
docker compose -f sims/docker-compose.yml up -d --build --wait
# clients: any container on the snmpnet network
docker run --rm --network snmpnet nfsnmp-sim-device:latest \
    snmpget -v2c -c public 172.31.161.11 1.3.6.1.2.1.1.2.0 1.3.6.1.4.1.318.1.1.1.2.3.2.0
sims/selftest.sh            # build + up + full self-test + down (KEEP_UP=1 keeps it running)
sims/tools/verify-oids.sh   # re-verify every served OID/type/access against the real MIBs
```

If your default buildx builder is a remote/cloud builder, prefix compose with
`BUILDX_BUILDER=default` (selftest.sh does this for you).

The compose stack publishes nothing on the host. `docker-compose.ports.yml` adds
loopback mappings: HTTP on `127.0.0.1:180NN` and SNMP on `127.0.0.1:161NN/udp`, where
NN is the last octet of the sim's address. Set `SIM_STEP_MS` to change the step for
all sims. Set `SIM_QUIRKY_FAULTS` to choose the quirky sim's startup faults.

| service | IP (network `snmpnet`, 172.31.161.0/24) | model | sysObjectID |
|---|---|---|---|
| sim-apc-ups | 172.31.161.11 | APC Smart-UPS 3000 + AP9631 NMC (PowerNet-MIB) | 1.3.6.1.4.1.318.1.3.2.12 (`smartUPS3000`) |
| sim-ups-rfc1628 | 172.31.161.12 | generic 3-phase UPS, UPS-MIB only | 1.3.6.1.4.1.99999.1.1 |
| sim-raritan-pdu | 172.31.161.13 | Raritan PX2-5145R (PDU2-MIB) | 1.3.6.1.4.1.13742.6 |
| sim-liebert-crac | 172.31.161.14 | Liebert DS CRAC (LIEBERT-GP) | 1.3.6.1.4.1.476.1.42 (`liebertGlobalProducts`) |
| sim-switch | 172.31.161.15 | Catalyst 2960-X: IF-MIB + ENTITY-MIB + ENTITY-SENSOR-MIB | 1.3.6.1.4.1.9.1.1208 (`cat29xxStack`) |
| sim-quirky | 172.31.161.16 | buggy agent, v1/v2c only | 1.3.6.1.4.1.99998.1 |

Every sim answers SNMP on UDP 161 and serves its HTTP API on TCP 8000. Docker's IPAM
hands out addresses for attached clients from `172.31.161.128/25`, so `.2`–`.127` are
free for static assignment.

## Credentials

- v1/v2c: `public` is read-only and `private` is read-write. Wrong communities are
  silently ignored.
- v3 users on the device sims. Auth pass `authpass123`, priv pass `privpass123`.
  Configured with `createUser` and verified by selftest:

| user | level | auth | priv | access |
|---|---|---|---|---|
| noauth | noAuthNoPriv | – | – | ro |
| authsha | authNoPriv | SHA | – | rw |
| md5des | authPriv | MD5 | DES | rw |
| shaaes | authPriv | SHA | AES-128 | rw |
| sha256aes | authPriv | SHA-256 | AES-128 | rw |
| sha512aes | authPriv | SHA-512 | AES-128 | rw |
| sha256aes256 | authPriv | SHA-256 | AES-256 (Blumenthal) | rw |

  Debian's snmpd is built `--with-openssl --enable-blumenthal-aes`. It supports
  MD5/SHA/SHA-224/256/384/512 and DES/AES/AES-192/AES-256 (Blumenthal). AES-256 Reeder
  (`aes256r`) is **not** supported. `GET /info` → `users` lists what is configured, using
  the §1 protocol names (e.g. `{"user":"sha256aes256","authProtocol":"sha256","privProtocol":"aes256b",...}`).
- Each sim has a fixed engine ID: `80001f8804` followed by the hex of
  `"nfsnmp-<model>"` (reported in `/info` as `engineID`). The sims use it as the
  authoritative engine for v3 traps.

## HTTP API (port 8000)

- `GET /info` returns `model`, `simModel`, `sysObjectID`, `sysDescr`, `stepMs`,
  `engineID`, `communities`, `users`, `writable`, `roots` and `trapOID`.
  - `writable` lists the writable instance OIDs that currently exist.
  - `roots` lists the subtrees the model serves.
  - The quirky sim also reports `faults`, `faultKinds` and packet `stats`.
- `GET /truth?at=<unix_ms>` returns `{at, step, stepMs, raw, eng}`.
  - `step = floor(at/stepMs)`.
  - `raw` uses the §1 `{type,value}` format for every OID the model serves. It also
    includes `sysDescr.0`, `sysObjectID.0` and `sysName.0`, which snmpd serves from the
    generated config, and the writable `sysContact.0` and `sysLocation.0`. snmpd's own
    MIBs (sysUpTime, IP/HOST/UCD-MIB, …) are not in the truth.
  - `eng` is keyed `<MIB object name>.<index>`. Each entry is
    `{"value": <physical value>, "units": "...", "enum": "<label>"}`. Strings appear as
    `{"value": "<text>"}`, or hex when the value is not UTF-8. A sensor that has no
    reading has `"value": null`.
- `POST /trap {"target":"host:port","version":"1"|"2c"|"3","inform":bool,"user":"shaaes","community":"public"}`
  sends the model's characteristic notification with `snmptrap`/`snmpinform`. The
  response echoes `trapOID`, the normalized `varbinds`, and, for v1, the
  `enterprise/generic/specific` mapping (RFC 3584). v3 traps are sent with `-e <engineID>`.
  v3 informs use the receiver's engine.
- `POST /reset` clears all SNMP writes. On the quirky sim it also restores the env
  default faults.
- `POST /set-fault` is available on the quirky sim only (see below).

Values are pure functions of `floor(t/stepMs)`, so `/truth?at=` can be recomputed for
any instant. Each value is a smooth sinusoid plus SHA-256-keyed noise per step. Counters
are closed-form integrals of a positive rate. SNMP writes persist in memory
(`/run/sim/state.json`, shared by snmpd's pass_persist and the HTTP server), show up in
`/truth`, and survive snmpd restarts but not container restarts.

## Models and OIDs

Scaling matches the real devices. `eng` holds the physical value after scaling.

### sim-apc-ups (PowerNet-MIB, `1.3.6.1.4.1.318.1.1.1`)
- `upsAdv*` values are whole units. `upsHighPrec*` values are **tenths** (e.g.
  `upsHighPrecBatteryTemperature.0` = 273 → 27.3 degC).
- `upsAdvBatteryRunTimeRemaining.0` and `upsBasicBatteryTimeOnBattery.0` are
  **TimeTicks** (centiseconds).
- `upsBasicOutputStatus.0` is an enum: 2 = onLine, 3 = onBattery. The UPS goes on
  battery for 3 minutes every 30 minutes (minutes 10–13 of each half hour, UTC).
  `upsBasicBatteryStatus` (2/3) and capacity follow it.
- Objects: upsBasicIdentModel/Name (.1.1.1/.2), upsAdvIdentFirmwareRevision/
  DateOfManufacture/SerialNumber (.1.2.1–3), upsBasicBatteryStatus (.2.1.1),
  upsBasicBatteryTimeOnBattery (.2.1.2), upsAdvBatteryCapacity/Temperature/
  RunTimeRemaining/ReplaceIndicator (.2.2.1–4), upsAdvBatteryNominalVoltage/ActualVoltage
  (.2.2.7/.8), upsHighPrecBatteryCapacity/Temperature/NominalVoltage/ActualVoltage
  (.2.3.1–4), upsAdvInputLineVoltage/Frequency (.3.2.1/.4), upsHighPrecInputLineVoltage/
  Frequency (.3.3.1/.4), upsBasicOutputStatus (.4.1.1), upsAdvOutputVoltage/Frequency/
  Load/Current (.4.2.1–4), upsHighPrecOutputVoltage/Frequency/Load/Current (.4.3.1–4).
- Trap: `upsOnBattery`, a TRAP-TYPE with ENTERPRISE apc and specific 5. In v2 it is sent
  as `1.3.6.1.4.1.318.0.5` with `mtrapargsString.0` (`1.3.6.1.4.1.318.2.3.3.0`).

### sim-ups-rfc1628 (UPS-MIB, `1.3.6.1.2.1.33`)
- Frequencies (`upsInputFrequency`, `upsOutputFrequency`) are in **0.1 Hz**.
- `upsBatteryVoltage` is in 0.1 V DC. `upsInputCurrent`, `upsOutputCurrent` and
  `upsBatteryCurrent` are in 0.1 A.
- Voltages, power, %, minutes and degC are whole units.
- `upsInputTable` (`.1.3.3.1`) and `upsOutputTable` (`.1.4.4.1`) each have 3 rows
  (phases).
- Enums: `upsBatteryStatus`, `upsOutputSource`.
- `upsInputLineBads` is a Counter32.
- Trap: `upsTrapOnBattery` `1.3.6.1.2.1.33.2.1` with upsEstimatedMinutesRemaining,
  upsSecondsOnBattery and upsConfigLowBattTime.

### sim-raritan-pdu (PDU2-MIB, `1.3.6.1.4.1.13742.6`)
- One inlet and 8 outlets. Outlet names: `outletName` (`.3.5.3.1.3.1.N`) is a
  **writable** DisplayString, and outlet 8 starts empty.
  `outletLabel` (`.3.5.3.1.2.1.N`) holds "1".."8".
- `measurementsInletSensorValue` (`.5.2.3.1.4.1.1.<type>`) and
  `measurementsOutletSensorValue` (`.5.4.3.1.4.1.N.<type>`) are Unsigned32. Divide them by
  `10^inletSensorDecimalDigits` / `10^outletSensorDecimalDigits` (`.3.3.4.1.7`,
  `.3.5.4.1.7`, same index):

  | sensorType | decimal digits | units |
  |---|---|---|
  | rmsCurrent (1) | 3 | A |
  | rmsVoltage (4) | 0 | V |
  | activePower (5) | 0 | W |
  | apparentPower (6) | 0 | VA |
  | powerFactor (7) | 2 | – |
  | activeEnergy (8) | 0 | Wh |
  | frequency (23) | 1 | Hz |

  Outlets have 1/4/5/7, plus onOff (14). The onOff sensor has only a
  measurements…State (on 7 / off 8) and **no** Value row, like the real PDU.
- `*SensorUnits` (`.6`) carry the units enum. `measurements…IsAvailable`/`State` exist
  for every sensor.
- Switching: `switchingOperation` (`.4.1.2.1.2.1.N`, rw).
  - Values are off(0), on(1) and cycle(2). Cycle ends on and reads back 1.
  - `outletSwitchingState` (`.4.1.2.1.3`) shows on(7) or off(8).
  - `outletSwitchingTimeStamp` (`.4.1.2.1.4`) holds the unix seconds of the last switch.
  - A switched-off outlet reads 0 A, 0 W and pf 0. Outlet 8 starts off.
- Trap: `outletSensorStateChange` `1.3.6.1.4.1.13742.6.0.63`. Its varbinds are a subset:
  pduName, outletLabel, typeOfSensor.0, measurementsOutletSensorState and oldSensorState.0.

### sim-liebert-crac (LIEBERT-GP-ENVIRONMENTAL-MIB / -CONDITIONS-MIB, `1.3.6.1.4.1.476.1.42.3`)
- Setpoints are **writable** Integer32:
  - `lgpEnvTemperatureSettingDegC.0` (`.4.1.3.1.0`, range 10..35, default 22).
  - `lgpEnvHumiditySettingRel.0` (`.4.2.2.1.0`, range 20..80, default 45).
  - The controlled temperatures follow the setpoint.
- Temperature table `lgpEnvTemperatureTableDegC` (`.4.1.3.3.1`) has 3 rows: control,
  return and supply air. Each row has an Id, a Descr (OID pointing at the well-known
  `lgpEnv…Temperature`), MeasurementDegC (whole degrees), High/LowThreshold and
  **MeasurementTenthsDegC** (`.50`, tenths).
- Humidity table `lgpEnvHumidityTableRel` (`.4.2.2.3.1`) has the same structure,
  including `.50` in tenths of %RH.
- State enums `lgpEnvState*` (`.4.3.x`): system on/off/standby, plus cooling, heating,
  humidifying, dehumidifying, fan and generalAlarmOutput (each on/off). Also
  CoolingCapacity in %.
- Alarms: `lgpConditionsPresent.0` and `lgpConditionsTable` (`.2.3.1`).
  - `ChangeFilter` is always present (warning/minor).
  - A `HighTemperature` condition (alarm/major) appears during a 4-minute hot
    excursion every 20 minutes. Rows come and go, and the alarm row's index changes per
    excursion.
- Trap: `lgpEventConditionEntryAdded` `1.3.6.1.4.1.476.1.42.3.3.0.1` with
  lgpConditionId, lgpConditionDescr and lgpConditionTime.

### sim-switch (IF-MIB, ENTITY-MIB, ENTITY-SENSOR-MIB)
- snmpd's own IF-MIB modules are disabled (`-I -ifTable,ifXTable,interfaces,if-mib`). The
  model owns `.1.3.6.1.2.1.2`, `.31`, `.47` and `.99` through pass_persist at priority 1.
  The rest of snmpd (IP-MIB, HOST-RESOURCES, UCD) is still present.
- Interfaces use sparse ifIndex values:
  - 1 = Vlan1
  - 10101–10104 = Gi1/0/1–4. Gi1/0/3 is oper-down with frozen counters; Gi1/0/4 is
    admin-down.
  - 10601 = Te1/0/1. `ifSpeed` is clamped at 4294967295; `ifHighSpeed` = 10000.
- Columns:
  - ifTable: ifIndex/Descr/Type/Mtu/Speed/PhysAddress (6 binary bytes)/AdminStatus/
    OperStatus/LastChange, ifIn/OutOctets, ifIn/OutUcastPkts, ifInDiscards/Errors and
    ifOutErrors.
  - ifXTable: ifName, ifHCIn/OutOctets, ifHCIn/OutUcastPkts, ifHighSpeed,
    ifConnectorPresent and **ifAlias** (rw).
- `ifInOctets` = `ifHCInOctets mod 2^32`, at roughly 9–48 MB/s. The Counter32 wraps
  every 1.5–4 minutes; Gi1/0/1 wraps every ≈80 s. Te1/0/1's HC counters carry a
  **2^60 offset (> 2^53)** to exercise exact Counter64 handling.
- `entPhysicalTable`: chassis 1001 and sensors 1005–1041. `entPhysicalVendorType` uses
  real CISCO-ENTITY-VENDORTYPE-OID-MIB OIDs; the humidity sensor uses zeroDotZero.
- `entPhySensorTable` (`.99.1.1.1`). The value is
  `entPhySensorValue × 10^(3·(scale−9)) × 10^(−precision)`. exa and peta use their
  RFC 3433 values (10^18 and 10^15).

  | index | sensor | type | scale | precision | example |
  |---|---|---|---|---|---|
  | 1005 | inlet temp | celsius | units | 1 | 274 → 27.4 °C |
  | 1006 | hotspot temp | celsius | units | 0 | |
  | 1010 | PSU Vout | voltsDC | **milli** | 0 | 12034 → 12.034 V |
  | 1011 | PSU Iout | amperes | units | 2 | |
  | 1012 | PSU Pin | watts | units | 0 | |
  | 1020 | fan 1 | rpm | units | 0 | |
  | 1021 | fan 2 | rpm | units | 0 | **nonoperational(3)**, eng `null` |
  | 1030 | humidity | percentRH | units | 1 | |
  | 1040 | SFP Vcc | voltsDC | **micro** | 0 | |
  | 1041 | SFP Tx bias | amperes | milli | 1 | 65 → 0.0065 A |
- Trap: IF-MIB `linkDown` `1.3.6.1.6.3.1.1.5.3` with ifIndex, ifAdminStatus and
  ifOperStatus for 10103. In v1 it is generic trap 2.

### sim-quirky (synthetic, `1.3.6.1.4.1.99998`)
- System group: sysDescr, sysObjectID, sysUpTime, sysContact (rw), sysName,
  sysLocation (rw) and sysServices.
  - sysUpTime is measured from 00:00 UTC of the step's day, so it is deterministic.
- `qtSensorTable` `1.3.6.1.4.1.99998.1.1.1.1.<col>.<1..50>` (rows set by
  `SIM_QUIRKY_ROWS`). Columns:
  - qtIndex (1) Integer
  - qtName (2) "sensor-NN"
  - qtTemperature (3) Integer in tenths of degC, or a string under `floatAsString`
  - qtValue (4) Gauge32 %
  - qtOctets (5) Counter32
  - qtOctetsHC (6) Counter64, same value unwrapped
  - qtSetpoint (7) Integer, rw, range 10..35
- Scalar `qtRowCount.0` (`…99998.1.1.2.0`).
- Trap: coldStart (v1: generic 0, enterprise = sysObjectID).

## Quirk faults (sim-quirky)

| kind | parameter (default) | effect |
|---|---|---|
| `bulkIgnoresMaxRep` | `n` (200) | GETBULK returns `n` repetitions whatever max-repetitions says (stops only at end of MIB; capped near 2000 varbinds) |
| `bulkCrashAboveN` | `n` (10) | GETBULK with max-repetitions > n is silently dropped |
| `nonIncreasing` | `oid` (`…99998.1.1.1.1.2.5`) | GETNEXT/GETBULK from `oid` returns `oid` again, so the walk loops |
| `dropRate` | `value` (0..1) | that fraction of requests is silently dropped |
| `delayMs` | `value` | every response is delayed |
| `tooBigAboveN` | `n` (5) | `tooBig` for any response with more than n varbinds (v2c: empty varbind list per RFC 3416; v1: echoed) |
| `counter32Wrap` | `rate` (50e6 B/s) | qtOctets counts fast and wraps every ≈86 s |
| `floatAsString` | – | qtTemperature becomes a DisplayString such as `"23.5 C"` (eng still numeric) |
| `noSuchInstanceGaps` | – | qtValue is missing for rows with index % 4 == 3 (v2c noSuchInstance, v1 noSuchName, skipped by GETNEXT) |

Ways to set faults:
- `POST /set-fault {"kind":"bulkCrashAboveN","n":10}`
- `{"kind":"dropRate","value":0.3}`
- `{"kind":"floatAsString"}`
- `{"kind":"delayMs","enabled":false}` turns a fault off.
- `{"kind":"clear"}` turns all faults off.
- Startup defaults come from env `SIM_FAULTS`, either as JSON
  (`{"delayMs":100,"noSuchInstanceGaps":true}`) or as a list
  (`delayMs=100,noSuchInstanceGaps`). `POST /reset` restores these defaults.

The faults change `/truth` too: gaps vanish from `raw`, and `floatAsString` changes the
type. Other quirky behaviour:
- v1 GET/GETNEXT never return Counter64; qtOctetsHC is skipped or returns noSuchName.
- SET with `public` returns noAccess (v2c) or noSuchName (v1).
- v3 is not answered.

## Where the OIDs were verified

Every object, notification and reference OID that the device models serve is checked
by `tools/verify-oids.sh`, which reported **175 objects checked, 0 problems**.
- It fetches the MIB text from the LibreNMS MIB collection (pinned commit
  `1c22ea7cae6e`, `https://raw.githubusercontent.com/librenms/librenms/<ref>/mibs/...`).
- It runs net-snmp's `snmptranslate` against those MIBs inside the sim image.
- For each object it checks that `MIB::name` resolves to exactly the model's OID, that
  the SMI base type matches the served type (Unsigned32 is served as Gauge32), and that
  objects the model treats as writable are read-write in the MIB.

| model | MIB files (LibreNMS path) |
|---|---|
| APC | `apc/PowerNet-MIB` (objects, `smartUPS3000`, `upsOnBattery`/`mtrapargsString`) |
| RFC 1628 | `UPS-MIB` |
| Raritan | `raritan/PDU2-MIB` (tables, `switchingOperation`, `outletSensorStateChange`, `typeOfSensor`, `oldSensorState`) |
| Liebert | `liebert/LIEBERT-GP-{REGISTRATION,ENVIRONMENTAL,CONDITIONS,NOTIFICATIONS}-MIB` |
| switch | `IF-MIB`, `ENTITY-MIB`, `ENTITY-SENSOR-MIB`, `cisco/CISCO-PRODUCTS-MIB` (`cat29xxStack`), `cisco/CISCO-ENTITY-VENDORTYPE-OID-MIB` |

The SMI base modules (SNMPv2-SMI/TC/CONF, RFC1155-SMI, …) come from the same collection.
The scaling semantics come from the MIB DESCRIPTION clauses:
- APC HighPrec tenths
- RFC 1628 0.1 Hz / 0.1 A / 0.1 V
- Raritan "scaled by *SensorDecimalDigits"
- Liebert `…Tenths…` columns
- RFC 3433 scale/precision

## Self-test

`sims/selftest.sh` builds and starts the stack. It then runs `selftest.py` in a
`docker run --rm --network snmpnet` client container, which has the net-snmp CLI and
snmptrapd. For every sim the test does the following:
- The v2c system group and full v2c bulkwalks of every model root are compared with
  `/truth` for the same step. The test retries if a step boundary falls inside a request.
- A v1 walk is compared with the truth minus Counter64.
- Each v3 user does a GET.
- Writes are checked:
  - sysLocation via `private`, and sysContact via v3 `sha512aes`.
  - Read-only community and read-only user are rejected.
  - Raritan outlet switching and name, Liebert setpoint (including out-of-range
    wrongValue), and switch ifAlias.
  - `/reset` restores the defaults.
- Traps (v1, v2c, v2c inform, v3 trap with `shaaes`, v3 inform with `sha256aes`) are
  received by snmptrapd.
- Switch counters are checked: the Counter32/Counter64 relation, wrap time, and > 2^53.
- Every quirky fault is exercised, including GETBULK under `bulkIgnoresMaxRep` compared
  with the truth, and a bulkwalk under gaps + floatAsString + counter32Wrap.

Last run: **162 passed, 0 failed** (about 1 minute).
