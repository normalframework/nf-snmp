# difftest — differential testing of SNMP client implementations

Contract: `docs/internals.md` §1 (normalized varbind JSON, ops, target JSON) and §3.

```
difftest/
  Dockerfile            image: net-snmp 5.9.3 tools + snmpd, ref-gosnmp, ref-pysnmp, Node 22
  run.sh                host wrapper: build image, pick network, start extra agents, run run.js
  run.js                harness (Node stdlib only), runs inside the image
  matrix.json           targets x credentials x cases
  allowlist.json        known divergences, each with a reason
  refs/netsnmp/         ref-netsnmp: wraps snmpget/snmpgetnext/snmpbulkget/snmpset
  refs/gosnmp/          ref-gosnmp: github.com/gosnmp/gosnmp v1.47.0
  refs/pysnmp/          ref-pysnmp: pysnmp 7.1.32 (LeXtudio), asyncio v3arch hlapi
  agent/                real-snmpd config (stock net-snmp agent) and edge_agent.py
  out/report.json       last run (full outputs of every impl for every case)
test/difftest/difftest.test.js   vitest: harness logic; full matrix with DIFFTEST=1
```

## Running

```sh
difftest/run.sh                       # whole matrix, fails on un-allowlisted diffs
difftest/run.sh -v --targets 'sim-.*' --cases 'system-.*' --creds 'v2c|v1'
difftest/run.sh --impls netsnmp,gosnmp,pysnmp     # refs only
difftest/run.sh --list                # print the expanded plan
DIFFTEST=1 npx vitest run test/difftest
```

Network: `$SNMPNET`, else the first docker network named `snmpnet` or `*_snmpnet` (the sims
compose), else a throwaway `nfsnmp-dt-net`. Targets whose host does not resolve on that network
are skipped (reported). `run.sh` also starts two extra agents on the network:

- `real-snmpd` (container `nfsnmp-dt-real-snmpd`): stock net-snmp `snmpd` (HOST-RESOURCES,
  IF-MIB, SNMP framework MIBs) with the §2 communities/users plus `shaaes256`
  (SHA-1 + AES-256 Blumenthal, to tell the AES-256 key-extension variants apart).
- `edge-agent` (container `nfsnmp-dt-edge`): `agent/edge_agent.py`, a hand-rolled v1/v2c agent
  serving encoding edge cases (Counter64 max, empty/binary/long OctetString, raw/float/double/
  empty Opaque, Integer extremes, 2^32-1 OID arc, Null) plus a non-increasing subtree, an
  equal-OID GETNEXT, end-of-MIB, and an OID answered after 1.5 s (case `get-late-response`,
  timeout 1 s + 1 retry: the reply to the first transmission arrives in the retry window).

`sim-quirky+<fault>` targets run the quirky sim with a fault preset: the harness POSTs
`/set-fault` before that target's cases and clears it afterwards (variants of one host run
sequentially; different hosts run in parallel). Note this changes shared sim state.

The `ours` implementation (`node /app/bin/nf-snmp.js <op> --json`) is skipped automatically if
`bin/nf-snmp.js` does not exist.

## Request (stdin of every client)

```json
{"target": {...§1 target...}, "op": "get|walk|bulkwalk|set", "oids": ["..."], "root": "...",
 "maxRepetitions": 10, "varbinds": [{"oid": "...", "type": "Integer", "value": "1"}]}
```

Output: §1 JSON lines; exit 0 even on SNMP errors (exit 2 only for a malformed request).

## Shared semantics (all references implement these identically)

Walk (`walk` = GETNEXT, `bulkwalk` = GETBULK non-repeaters 0, max-repetitions N), starting with
`last = root`; for each returned varbind, in order:

1. `endOfMibView` / `noSuchObject` / `noSuchInstance` → stop (not emitted, no error).
2. OID not strictly inside the root subtree (`root.` prefix; the root itself counts as outside)
   → stop silently.
3. OID ≤ `last` → emit `{"error":"nonIncreasing"}` and stop.
4. emit, `last = oid`. Next request starts at `last`.

Also: an empty response stops the walk; a v1 GETNEXT `noSuchName` is end-of-MIB (no error line);
any other error-status/transport error is emitted as the error line (after the varbinds emitted
so far); no GET fallback when the walk is empty (unlike `snmpwalk`); `bulkwalk` with version 1 →
`{"error":"other"}` without sending anything; safety cap 200000 varbinds.

Error lines: `{"error": class, "message", "status"?, "index"?}`. `status` is the RFC 3416
error-status name and `index` the 1-based error-index, added when the agent returned an
error-status (the harness compares them only when both sides report them). Class mapping:
`tooBig noSuchName badValue readOnly genErr noAccess wrongType notWritable` map to themselves,
`authorizationError` → `noAccess`, every other status (`wrongValue`, `noCreation`,
`inconsistentValue`, `wrongLength`, ...) → `other`. USM failures (unknown user, wrong digest,
unsupported security level, decryption error, not in time window) → `authError`; no response →
`timeout`.

## Per-implementation caveats

**ref-netsnmp** (net-snmp 5.9.3 CLI, Debian bookworm)
- Flags `-On -Oe -Ox -OU -Op .17g`, `MIBS=""`. `-Ot` is not used: without MIBs it drops the
  `Timeticks:` tag entirely, so the parser reads `Timeticks: (N) ...` instead.
- `-Ox` hex output wraps every 16 bytes; continuation lines are joined. Empty strings print `""`.
- Opaque floats/doubles (net-snmp extension, `9f78`/`9f79`) are decoded by net-snmp and printed as
  `Opaque: Float: x` **for both float and double**; the ref re-encodes to the raw Opaque content,
  choosing float when the number round-trips through float32 (a double holding a
  float32-representable value would be mis-labelled → allowlisted if it ever occurs).
  Plain Opaque prints as `OPAQUE: hex`.
- `snmpget -Cf` so net-snmp does not silently drop the failing varbind and retry.
- No `Counter32`/`Counter64`/`Opaque` SET (snmpset has no type letter for them) → error `other`.
- v3 priv names: `aes256b` → `-x AES-256` (Blumenthal), `aes256r` → `-x AES256C` (Reeder).
- Each GETNEXT/GETBULK of a walk is a separate process (so v3 does engine discovery per step).

**ref-gosnmp** (gosnmp v1.47.0)
- Report PDUs (usmStats*) are returned by gosnmp as a result, not an error; the ref maps them
  to `authError`. Wrong auth key typically surfaces as "incoming packet is not authentic".
- OpaqueFloat/OpaqueDouble are decoded by gosnmp; re-encoded to raw Opaque content (exact).
- `aes256b` → `AES256` (Blumenthal), `aes256r` → `AES256C` (Reeder).
- SET of Opaque unsupported by gosnmp → error `other`.

**ref-pysnmp** (pysnmp 7.1.32, cryptography 50)
- pysnmp turns v1 responses into SMIv2 (RFC 2576): a v1 `noSuchName` keeps its error-status,
  varbinds are rewritten; the ref acts on the error-status only.
- `aes256b` → `USM_PRIV_CFB256_AES_BLUMENTHAL`, `aes256r` → `USM_PRIV_CFB256_AES` (pysnmp's
  plain "AES256" constant is the *Reeder* variant).
- pysnmp ≥ 7.1 needs `cryptography` with `hazmat.decrepit.ciphers.modes` (≥ 47); older
  versions fail every privacy request with "Ciphering services not available".

## Time-varying values

Sims quantize values to `stepMs` (from `GET /info`). Every case runs all impls back-to-back,
records whether the case stayed within one step, and re-runs (up to `--attempts`, default 3) any
case with un-allowlisted diffs; a case that passes on a re-run is reported as `flaky`. For sims
each impl's varbinds are also checked against `GET /truth?at=<case start>` (report key
`truthMismatches`; informational, not a failure). For agents, `volatile` OID prefixes (matrix
global + per-target) compare by type only and ignore missing/extra rows.

Sim per-target variables are derived automatically: `enterprise` from `sysObjectID`, `roots`
from the distinct subtrees in `/truth.raw`, `mixed` (one OID per type), `writable` (from
`/info.writable`, set to the current truth value so SETs are idempotent), `wrongtype`.
