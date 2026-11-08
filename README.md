# nf-snmp — SNMP for Normal Framework

An NF app that polls and trends SNMP devices — UPSes, PDUs, cooling units, network gear — using
built-in device profiles, with discovery, traps/informs and (allow-listed) SET.

License: **GPL-3.0-or-later** (see `LICENSE`). MIB files under `mibs/` are from the LibreNMS
collection and keep their vendors' copyright; they are used only by tests and tooling, never at runtime.

## How it works

```
NF poll service ──POST /driver/read──▶ engine ──SNMP GET──▶ device
NF command svc  ──POST /driver/write─▶ engine ──SNMP SET──▶ device   (writable profile symbols only)
device ──trap/inform UDP 162──▶ engine ──AddData──▶ <device> snmpTrap point
admin console UI ──admin hook──▶ engine /admin/*  (devices, discovery, explore, traps, profiles)
```

- The app declares an indexed layer **`snmp`** whose driver is the engine's localhost HTTP API with
  `polled: true`, so NF's own poll service schedules reads (per point `period`, per-host limits on
  `device_address`) and stores the time series — the same path as the built-in Modbus driver.
- Adding a device identifies it (`sysObjectID`, `sysDescr`), picks a profile, expands profile tables
  by walking them, and publishes one NF point per value (plus a device point and an `snmpTrap` point).
  Objects the device reports as nonexistent (firmware/model variation) are dropped with a warning;
  text-valued symbols (model, firmware) become attributes of the device point, since NF trends
  numbers only. Values are sent as `double` (NF stores float64; `real` would round through float32).
- SNMPv3 DES privacy uses a bundled pure-JS DES (`lib/snmp/des.js`): Node's OpenSSL 3 has no DES.
- User profiles: `POST` via the admin hook (`put-profile`) into `local/profiles/`; built-in ids
  cannot be shadowed.
- **Self-poll fallback:** NF's poll service lists polled layers when it starts, so a freshly installed
  app's layer is not polled until NF restarts. Until NF's first `/driver/read`, the engine polls on its
  own and pushes data via AddData; it stands down automatically when NF takes over.

## Install

From the NF admin console (Applications → add from git), or from a checkout:

```
npm install
NF_URL=http://<gateway>:8080 [NF_TOKEN=…] npm run install:nf
```

Restart NF once after the first install so its poll service picks up the `snmp` layer (until then the
engine self-polls; the UI shows "self-polling").

Options (app settings): `enabled`, `logLevel`, `adminPort` (47081, must match `app.json`), `trapPort`
(162; 0 disables the receiver).

## Devices

Per device: host, port, version `1|2c|3`, community or USM user (auth `md5|sha|sha224|sha256|sha384|sha512`,
privacy `des|aes|aes256b|aes256r` — the two AES-256 key-localization variants used by different vendors),
profile (`auto` or an id), poll period, timeout/retries, max OIDs per GET (adaptive: halves on `tooBig`),
GETBULK repetitions, optional write community.

Point attributes on layer `snmp`: `device`, `device_uuid`, `device_address` (`SNMP:host:port`),
`profile`, `oid`, `symbol`, `index`, `units`, `class_hint`, `writable`, `enum`, `vendor`.
UUIDs are deterministic (uuidv5 of `host:port`, and of `device/oid`) so delete + re-add keeps history.

## Profiles

`profiles/<vendor>/<model>.json`, format in `docs/internals.md` §4. Highlights:

- match by longest `sysObjectID` prefix, then `sysDescr` regex, then a `probe` OID
- scalars and tables (index walk, labels from a column or another table, `rowFilter`, `maxRows`)
- decoding: `scale`/`offset`, `displayHint d-N`, `decimalDigitsOid` (Raritan), `entitySensor`
  (RFC 3433 scale/precision/oper-status), `regex` (floats sent as strings), `sentinels`, `enum`,
  TimeTicks → seconds, per-row `unitsFrom`
- `writable` + `setType` for SET; writes are inverse-scaled

Built-in, hand-written and verified against independent device simulators (`sims/device`): APC
Smart-UPS (PowerNet-MIB), RFC 1628 UPS-MIB, Raritan PX PDU2-MIB, Vertiv Liebert GP environmental,
ENTITY-SENSOR-MIB, IF-MIB, generic switch.

Plus **162 device profiles imported from Datadog** (`profiles/datadog/`, BSD-3-Clause; see NOTICE):
UPSes and PDUs (APC, Eaton, ServerTech, Tripp Lite, CyberPower, Chatsworth, Raritan), cooling and
environment (Vertiv/Liebert, NetBotz, Watchdog), network, server and storage gear. Import pipeline
(`npm run profiles:import`):

1. `tools/import-datadog.mjs` converts the pinned originals in `vendor/datadog-profiles/`
   (wildcard sysObjectIDs, tables, cross-table labels, index transforms, counters) plus
   `vendor/datadog-overrides.json` (e.g. RFC 3433 decoding for `entPhySensorValue`).
2. `tools/fetch-mibs.mjs` pulls every referenced MIB and its imports from LibreNMS (pinned).
3. `tools/verify-profiles.mjs` checks each symbol with net-snmp's `snmptranslate`: OID wins over a
   wrong name (renamed), objects absent from the MIB are dropped (e.g. Datadog's BFD OIDs under
   mib-2.223; RFC 7330 is .222), and — where Datadog leaves values raw — units, scaling ("0.1 Volt
   DC", "tenths of degrees") and enum labels are taken from the MIB. Report:
   `profiles/datadog/VERIFICATION.md`. SET is never enabled for imported profiles.

Hand-written profiles outrank imported ones on equal matches; catch-all wildcards rank below a MIB probe.
`test/unit/profiles-mib.test.js` checks every symbol name against the real MIB so a right-name /
wrong-OID mistake cannot ship. `node tools/mib-oids.js <MODULE> <names…>` resolves names from `mibs/`.

## Discovery

Opt-in jobs over IPs, ranges and CIDRs (/16–/32, max 1024 hosts), at most 4 credential sets tried
in order, bounded concurrency. Results show vendor (IANA enterprise registry, `data/enterprises.tsv`),
`sysDescr`, matched profile and confidence; selected hosts become devices. Multi-community sweeps
look like attacks to IDS — keep ranges and credential lists small.

## Traps and informs

UDP `trapPort` (default 162). Each notification from a configured device's address increments that
device's numeric `snmpTrap` point (NF trends numbers only), and the trap OID + varbinds are written to
the point's `last_trap` / `last_trap_at` attributes. All notifications appear in the Traps tab.
SNMPv3: users of v3 devices are registered automatically; informs work as-is. v3 *traps* require the
sender to be configured with its engine ID on our side in most stacks — prefer informs.

## Development

```
npm test                       # unit tests (in-process agents, fake NF)
node bin/nf-snmp.js get --json  <<< '{"target":{"host":"…"},"oids":["1.3.6.1.2.1.1.1.0"]}'
node bin/nf-snmp.js identify --json <<< '{"target":{"host":"…"}}'
node bin/nf-snmp.js profile-read --json <<< '{"target":{"host":"…"}}'
sims/            synthetic devices (real net-snmp snmpd + models, quirk agent) — see sims/README.md
sims/generated/  generated simulator: every profile served from its MIB facts (npm run profiles:smoke;
                 report in sims/generated/REPORT.md)
difftest/        differential tests against net-snmp, gosnmp and pysnmp — see difftest/README.md
test/e2e/        full stack: NF + sims + this app
```
