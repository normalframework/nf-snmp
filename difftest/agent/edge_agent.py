#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""edge-agent: tiny hand-rolled SNMPv1/v2c agent serving encoding edge cases for difftest.

Not a device simulator (those live in sims/); it exists so the reference clients can be
compared on values that real agents rarely produce. Self-contained BER codec, no deps.

Tree (all under 1.3.6.1.4.1.99997):
  .1.N.0   value edge cases (Counter64 max, empty/long/binary OctetString, Opaque raw/float/
           double/empty, Integer extremes, OID with 2^32-1 arc, Null, ...)
  .2       non-increasing walk: GETNEXT(.2.2.0) returns .2.1.0 again
  .3       GETNEXT(.3.1.0) returns .3.1.0 itself (equal OID)
  .5.1.0   GET answered after 1.5 s (late-response / retransmission behaviour)
  .9.1.0   last object; GETNEXT past it -> endOfMibView (v2c) / noSuchName (v1)
Writable: .1.3.0 (OctetString), .1.7.0 (Integer).
Communities: public (ro), private (rw).  v1: Counter64 objects are skipped by GETNEXT and
return noSuchName on GET (RFC 2576 proxy behaviour).
"""
import socket
import struct
import sys
import threading

BASE = (1, 3, 6, 1, 4, 1, 99997)

# tags
INT, OCT, NUL, OID, SEQ = 0x02, 0x04, 0x05, 0x06, 0x30
IPA, C32, G32, TT, OPQ, C64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
NSO, NSI, EOM = 0x80, 0x81, 0x82
GET, NEXT, RESP, SET, BULK = 0xA0, 0xA1, 0xA2, 0xA3, 0xA5


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + enc_len(len(body)) + body


def enc_int(tag, v):
    if v == 0:
        return tlv(tag, b"\x00")
    n = (v.bit_length() + 8) // 8
    b = v.to_bytes(n, "big", signed=True)
    # minimal encoding
    while len(b) > 1 and ((b[0] == 0 and b[1] < 0x80) or (b[0] == 0xFF and b[1] >= 0x80)):
        b = b[1:]
    return tlv(tag, b)


def enc_uint(tag, v):
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
    while len(b) > 1 and b[0] == 0 and b[1] < 0x80:
        b = b[1:]
    return tlv(tag, b)


def enc_oid(arcs):
    out = bytearray([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(chunk))
    return tlv(OID, bytes(out))


def dec(buf, i):
    tag = buf[i]
    i += 1
    ln = buf[i]
    i += 1
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + ln], i + ln


def dec_int(b):
    return int.from_bytes(b, "big", signed=True)


def dec_oid(b):
    arcs = [b[0] // 40, b[0] % 40]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            arcs.append(v)
            v = 0
    return tuple(arcs)


def o(*a):
    return BASE + a


# value = (tag, encoded-bytes-of-whole-TLV)
VALUES = {
    o(1, 1, 0): (C64, enc_uint(C64, 2 ** 64 - 1)),
    o(1, 2, 0): (C64, enc_uint(C64, 0)),
    o(1, 3, 0): (OCT, tlv(OCT, b"")),
    o(1, 4, 0): (OPQ, tlv(OPQ, bytes.fromhex("0102ff"))),
    o(1, 5, 0): (OPQ, tlv(OPQ, bytes.fromhex("9f7804") + struct.pack(">f", 23.5))),
    o(1, 6, 0): (OPQ, tlv(OPQ, bytes.fromhex("9f7908") + struct.pack(">d", -0.1))),
    o(1, 7, 0): (INT, enc_int(INT, -2147483648)),
    o(1, 8, 0): (INT, enc_int(INT, 2147483647)),
    o(1, 9, 0): (G32, enc_uint(G32, 2 ** 32 - 1)),
    o(1, 10, 0): (TT, enc_uint(TT, 2 ** 32 - 1)),
    o(1, 11, 0): (IPA, tlv(IPA, bytes([0, 0, 0, 0]))),
    o(1, 12, 0): (OID, enc_oid((0, 0))),
    o(1, 13, 0): (OID, enc_oid((1, 3, 6, 1, 4, 1, 2 ** 32 - 1))),
    o(1, 14, 0): (OCT, tlv(OCT, bytes.fromhex("00ff0a0d22275c"))),
    o(1, 15, 0): (OCT, tlv(OCT, "23.5 °C".encode())),
    o(1, 16, 0): (NUL, tlv(NUL, b"")),
    o(1, 17, 0): (C32, enc_uint(C32, 2 ** 32 - 1)),
    o(1, 18, 0): (OCT, tlv(OCT, bytes(range(256)) + b"tail" * 20)),
    o(1, 19, 0): (OPQ, tlv(OPQ, b"")),
    o(1, 20, 0): (OCT, tlv(OCT, b"23.5 C")),
    o(1, 21, 0): (INT, enc_int(INT, 0)),
    o(2, 1, 0): (INT, enc_int(INT, 1)),
    o(2, 2, 0): (INT, enc_int(INT, 2)),
    o(3, 1, 0): (INT, enc_int(INT, 3)),
    o(5, 1, 0): (INT, enc_int(INT, 5)),
    o(9, 1, 0): (INT, enc_int(INT, 9)),
}
DELAY_S = {o(5, 1, 0): 1.5}
WRITABLE = {o(1, 3, 0): OCT, o(1, 7, 0): INT}
NEXT_OVERRIDE = {o(2, 2, 0): o(2, 1, 0), o(3, 1, 0): o(3, 1, 0)}
ORDER = sorted(VALUES)


def getnext(q, v1):
    if q in NEXT_OVERRIDE:
        return NEXT_OVERRIDE[q]
    for k in ORDER:
        if k > q and not (v1 and VALUES[k][0] == C64):
            return k
    return None


def delay_for(pkt):
    """Seconds to delay the response (any requested OID in DELAY_S)."""
    try:
        return max((DELAY_S[k] for k in DELAY_S if enc_oid(k) in pkt), default=0)
    except Exception:  # noqa: BLE001
        return 0


def handle(pkt):
    _, msg, _ = dec(pkt, 0)
    t, b, i = dec(msg, 0)
    version = dec_int(b)
    t, community, i = dec(msg, i)
    pdu_tag, pdu, _ = dec(msg, i)
    v1 = version == 0
    if community not in (b"public", b"private"):
        return None
    t, b, j = dec(pdu, 0)
    reqid = dec_int(b)
    t, b, j = dec(pdu, j)
    p1 = dec_int(b)
    t, b, j = dec(pdu, j)
    p2 = dec_int(b)
    t, vbl, j = dec(pdu, j)
    reqs = []
    k = 0
    while k < len(vbl):
        _, vb, k = dec(vbl, k)
        _, ob, m = dec(vb, 0)
        vt = vb[m]
        _, vv, _ = dec(vb, m)
        reqs.append((dec_oid(ob), vt, vb[m:]))
    out = []
    err, eidx = 0, 0

    def fail(code_v2, idx, code_v1=2):
        return (code_v1 if v1 else code_v2), idx

    if pdu_tag == GET:
        for n, (q, _, _) in enumerate(reqs, 1):
            val = VALUES.get(q)
            if val is None or (v1 and val[0] == C64):
                if v1:
                    err, eidx = 2, n
                    break
                out.append((q, tlv(NSO, b"")))
            else:
                out.append((q, val[1]))
    elif pdu_tag == NEXT:
        for n, (q, _, _) in enumerate(reqs, 1):
            nx = getnext(q, v1)
            if nx is None:
                if v1:
                    err, eidx = 2, n
                    break
                out.append((q, tlv(EOM, b"")))
            else:
                out.append((nx, VALUES[nx][1]))
    elif pdu_tag == BULK and not v1:
        nonrep, maxrep = max(p1, 0), max(p2, 0)
        for q, _, _ in reqs[:nonrep]:
            nx = getnext(q, False)
            out.append((nx, VALUES[nx][1]) if nx else (q, tlv(EOM, b"")))
        cur = [q for q, _, _ in reqs[nonrep:]]
        for _ in range(maxrep):
            if not cur:
                break
            nxt = []
            for q in cur:
                nx = getnext(q, False)
                if nx is None:
                    out.append((q, tlv(EOM, b"")))
                    nxt.append(q)
                else:
                    out.append((nx, VALUES[nx][1]))
                    nxt.append(nx)
            if all(v[1][0] == EOM for v in out[-len(cur):]):
                break
            cur = nxt
    elif pdu_tag == SET:
        if community != b"private":
            err, eidx = (2 if v1 else 6), 1  # v2: noAccess
        else:
            for n, (q, vt, raw) in enumerate(reqs, 1):
                if q not in VALUES:
                    err, eidx = fail(11, n)  # noCreation
                    break
                if q not in WRITABLE:
                    err, eidx = fail(17, n)  # notWritable
                    break
                if vt != WRITABLE[q]:
                    err, eidx = fail(7, n, 3)  # wrongType / v1 badValue
                    break
            if not err:
                for q, vt, raw in reqs:
                    VALUES[q] = (vt, raw)
                    out.append((q, raw))
    else:
        return None
    if err:
        out = [(q, raw) for q, _, raw in reqs]
    vbs = b"".join(tlv(SEQ, enc_oid(q) + v) for q, v in out)
    body = enc_int(INT, reqid) + enc_int(INT, err) + enc_int(INT, eidx) + tlv(SEQ, vbs)
    return tlv(SEQ, enc_int(INT, version) + tlv(OCT, community) + tlv(RESP, body))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 161
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    print("edge-agent listening on udp/%d" % port, flush=True)
    while True:
        pkt, addr = s.recvfrom(65535)
        try:
            r = handle(pkt)
        except Exception as e:  # noqa: BLE001
            print("bad packet from %s: %s" % (addr, e), flush=True)
            continue
        if r:
            d = delay_for(pkt)
            if d:
                threading.Timer(d, s.sendto, (r, addr)).start()
            else:
                s.sendto(r, addr)


if __name__ == "__main__":
    main()
