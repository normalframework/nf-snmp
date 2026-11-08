# Generated-simulator smoke test

Every profile is served by `sims/generated/gensimd.py` from a spec built out of the profile and its MIB, then
identified, materialized and read by nf-snmp; decoded values are compared with the simulator's truth.

| profiles | passed | failed | points | values compared | auto-match picked another profile |
|---|---|---|---|---|---|
| 169 | 169 | 0 | 23436 | 23191 | 6 |

## Failures

none

## Auto-match differs from the profile under test

Expected where a more specific or hand-written profile covers the same sysObjectID (e.g. several Datadog APC profiles share `1.3.6.1.4.1.318.1.*`).

- _generic/switch → _generic/entity-sensor
- dd/aruba-switch → dd/aruba-wireless-controller
- dd/generic-device → _generic/if-mib
- dd/meraki → dd/meraki-cloud-controller
- dd/riverbed → dd/riverbed-steelhead
- dd/vertiv-liebert-ac → vertiv/liebert-gp-env
