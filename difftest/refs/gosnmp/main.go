// SPDX-License-Identifier: GPL-3.0-or-later
//
// ref-gosnmp: difftest reference client built on github.com/gosnmp/gosnmp.
//
// Reads one JSON request on stdin and writes docs/internals.md §1 JSON lines to stdout.
// Exit status is 0 whenever a request was attempted (SNMP failures are JSON error lines);
// non-zero only for a malformed request.
//
// Walks are implemented here with explicit GETNEXT / GETBULK PDUs (not gosnmp's Walk/BulkWalk,
// which silently tolerate some agent bugs and use their own stop rules) so that the stop rules
// are exactly those of difftest/README.md "Walk semantics".
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type target struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Version      string `json:"version"`
	Community    string `json:"community"`
	User         string `json:"user"`
	AuthProtocol string `json:"authProtocol"`
	AuthKey      string `json:"authKey"`
	PrivProtocol string `json:"privProtocol"`
	PrivKey      string `json:"privKey"`
	TimeoutMs    int    `json:"timeoutMs"`
	Retries      *int   `json:"retries"`
	Context      string `json:"context"`
}

type varbindIn struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type request struct {
	Target         target      `json:"target"`
	Op             string      `json:"op"`
	OIDs           []string    `json:"oids"`
	Root           string      `json:"root"`
	MaxRepetitions int         `json:"maxRepetitions"`
	Varbinds       []varbindIn `json:"varbinds"`
}

var out = json.NewEncoder(os.Stdout)

func emitVB(oid, typ, value string) {
	out.Encode(map[string]string{"oid": oid, "type": typ, "value": value})
}

func emitErr(class, msg string, extra map[string]any) {
	m := map[string]any{"error": class, "message": msg}
	for k, v := range extra {
		m[k] = v
	}
	out.Encode(m)
}

// --- error status mapping (shared by all refs; see README) ---

var statusNames = []string{"noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr",
	"noAccess", "wrongType", "wrongLength", "wrongEncoding", "wrongValue", "noCreation",
	"inconsistentValue", "resourceUnavailable", "commitFailed", "undoFailed",
	"authorizationError", "notWritable", "inconsistentName"}

func statusClass(name string) string {
	switch name {
	case "tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess", "wrongType", "notWritable":
		return name
	case "authorizationError":
		return "noAccess"
	}
	return "other"
}

func emitStatus(st gosnmp.SNMPError, idx uint8) {
	name := fmt.Sprintf("status%d", int(st))
	if int(st) < len(statusNames) {
		name = statusNames[st]
	}
	emitErr(statusClass(name), name, map[string]any{"status": name, "index": int(idx)})
}

// --- OID helpers ---

func normOID(s string) string { return strings.TrimPrefix(strings.TrimSpace(s), ".") }

func parseOID(s string) []uint64 {
	s = normOID(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	r := make([]uint64, len(parts))
	for i, p := range parts {
		r[i], _ = strconv.ParseUint(p, 10, 64)
	}
	return r
}

func cmpOID(a, b []uint64) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return len(a) - len(b)
}

func inSubtree(oid, root []uint64) bool {
	if len(oid) <= len(root) {
		return false
	}
	for i := range root {
		if oid[i] != root[i] {
			return false
		}
	}
	return true
}

// --- value normalization ---

func toUint64String(v any) string {
	switch n := v.(type) {
	case uint64:
		return strconv.FormatUint(n, 10)
	case *big.Int:
		return n.String()
	}
	return gosnmp.ToBigInt(v).String()
}

// normalize returns (type, value) for a decoded PDU.
func normalize(p gosnmp.SnmpPDU) (string, string) {
	switch p.Type {
	case gosnmp.Integer:
		return "Integer", gosnmp.ToBigInt(p.Value).String()
	case gosnmp.OctetString, gosnmp.BitString:
		b, _ := p.Value.([]byte)
		return "OctetString", hex.EncodeToString(b)
	case gosnmp.ObjectIdentifier:
		s, _ := p.Value.(string)
		return "OID", normOID(s)
	case gosnmp.IPAddress:
		s, _ := p.Value.(string)
		return "IpAddress", s
	case gosnmp.Counter32:
		return "Counter32", toUint64String(p.Value)
	case gosnmp.Gauge32, gosnmp.Uinteger32:
		return "Gauge32", toUint64String(p.Value)
	case gosnmp.TimeTicks:
		return "TimeTicks", toUint64String(p.Value)
	case gosnmp.Counter64:
		return "Counter64", toUint64String(p.Value)
	case gosnmp.Opaque:
		b, _ := p.Value.([]byte)
		return "Opaque", hex.EncodeToString(b)
	case gosnmp.OpaqueFloat:
		// gosnmp decodes the net-snmp Opaque-float extension; re-encode the raw Opaque content.
		f, _ := p.Value.(float32)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, math.Float32bits(f))
		return "Opaque", "9f7804" + hex.EncodeToString(b)
	case gosnmp.OpaqueDouble:
		f, _ := p.Value.(float64)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, math.Float64bits(f))
		return "Opaque", "9f7908" + hex.EncodeToString(b)
	case gosnmp.Null:
		return "Null", ""
	case gosnmp.NoSuchObject:
		return "NoSuchObject", ""
	case gosnmp.NoSuchInstance:
		return "NoSuchInstance", ""
	case gosnmp.EndOfMibView:
		return "EndOfMibView", ""
	}
	return fmt.Sprintf("Unknown(0x%02x)", byte(p.Type)), fmt.Sprintf("%v", p.Value)
}

// --- client setup ---

func authProto(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToLower(s) {
	case "", "none":
		return gosnmp.NoAuth, nil
	case "md5":
		return gosnmp.MD5, nil
	case "sha":
		return gosnmp.SHA, nil
	case "sha224":
		return gosnmp.SHA224, nil
	case "sha256":
		return gosnmp.SHA256, nil
	case "sha384":
		return gosnmp.SHA384, nil
	case "sha512":
		return gosnmp.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported authProtocol %q", s)
}

func privProto(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToLower(s) {
	case "", "none":
		return gosnmp.NoPriv, nil
	case "des":
		return gosnmp.DES, nil
	case "aes":
		return gosnmp.AES, nil
	case "aes256b":
		return gosnmp.AES256, nil // Blumenthal key extension
	case "aes256r":
		return gosnmp.AES256C, nil // Reeder ("Cisco") key extension
	}
	return 0, fmt.Errorf("unsupported privProtocol %q", s)
}

func newClient(t target) (*gosnmp.GoSNMP, error) {
	port := t.Port
	if port == 0 {
		port = 161
	}
	timeout := t.TimeoutMs
	if timeout <= 0 {
		timeout = 2000
	}
	retries := 1
	if t.Retries != nil {
		retries = *t.Retries
	}
	g := &gosnmp.GoSNMP{
		Target:             t.Host,
		Port:               uint16(port),
		Community:          t.Community,
		Timeout:            time.Duration(timeout) * time.Millisecond,
		Retries:            retries,
		ExponentialTimeout: false,
		MaxOids:            1 << 16,
		MaxRepetitions:     10,
		Logger:             gosnmp.NewLogger(nil),
	}
	if g.Community == "" {
		g.Community = "public"
	}
	switch t.Version {
	case "1":
		g.Version = gosnmp.Version1
	case "2c", "2", "":
		g.Version = gosnmp.Version2c
	case "3":
		g.Version = gosnmp.Version3
		ap, err := authProto(t.AuthProtocol)
		if err != nil {
			return nil, err
		}
		pp, err := privProto(t.PrivProtocol)
		if err != nil {
			return nil, err
		}
		g.SecurityModel = gosnmp.UserSecurityModel
		g.ContextName = t.Context
		switch {
		case ap == gosnmp.NoAuth:
			g.MsgFlags = gosnmp.NoAuthNoPriv
		case pp == gosnmp.NoPriv:
			g.MsgFlags = gosnmp.AuthNoPriv
		default:
			g.MsgFlags = gosnmp.AuthPriv
		}
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 t.User,
			AuthenticationProtocol:   ap,
			AuthenticationPassphrase: t.AuthKey,
			PrivacyProtocol:          pp,
			PrivacyPassphrase:        t.PrivKey,
		}
	default:
		return nil, fmt.Errorf("unsupported version %q", t.Version)
	}
	return g, nil
}

// classifyErr maps a Go error from gosnmp into a §1 error class.
func classifyErr(err error) (string, string) {
	msg := err.Error()
	l := strings.ToLower(msg)
	var ne net.Error
	switch {
	case strings.Contains(l, "timeout") || (asNetErr(err, &ne) && ne.Timeout()):
		return "timeout", msg
	case strings.Contains(l, "not authentic") || strings.Contains(l, "authenticat") ||
		strings.Contains(l, "decrypt") || strings.Contains(l, "unknown engine") ||
		strings.Contains(l, "time window") || strings.Contains(l, "requires authentication"):
		return "authError", msg
	case strings.Contains(l, "connection refused"):
		// ICMP port unreachable surfaced on a connected UDP socket.
		return "timeout", msg
	case strings.Contains(l, "pars") || strings.Contains(l, "decod") || strings.Contains(l, "truncat") ||
		strings.Contains(l, "invalid"):
		return "decodeError", msg
	}
	return "other", msg
}

func asNetErr(err error, ne *net.Error) bool {
	e, ok := err.(net.Error)
	if ok {
		*ne = e
	}
	return ok
}

var usmReports = map[string]string{
	"1.3.6.1.6.3.15.1.1.1.0": "unsupportedSecLevels",
	"1.3.6.1.6.3.15.1.1.2.0": "notInTimeWindows",
	"1.3.6.1.6.3.15.1.1.3.0": "unknownUserNames",
	"1.3.6.1.6.3.15.1.1.4.0": "unknownEngineIDs",
	"1.3.6.1.6.3.15.1.1.5.0": "wrongDigests",
	"1.3.6.1.6.3.15.1.1.6.0": "decryptionErrors",
}

// checkResult handles transport errors, Report PDUs and error-status.
// Returns true if the caller should continue processing varbinds.
func checkResult(r *gosnmp.SnmpPacket, err error, walkV1 bool) (ok bool, endOfWalk bool) {
	if err != nil {
		c, m := classifyErr(err)
		emitErr(c, m, nil)
		return false, false
	}
	if r == nil {
		emitErr("other", "nil response", nil)
		return false, false
	}
	if r.PDUType == gosnmp.Report {
		name := ""
		if len(r.Variables) > 0 {
			name = normOID(r.Variables[0].Name)
		}
		if why, ok := usmReports[name]; ok {
			emitErr("authError", why, nil)
		} else {
			emitErr("other", "report "+name, nil)
		}
		return false, false
	}
	if r.Error != gosnmp.NoError {
		if walkV1 && r.Error == gosnmp.NoSuchName {
			return false, true // v1 end of MIB view
		}
		emitStatus(r.Error, r.ErrorIndex)
		return false, false
	}
	return true, false
}

func doGet(g *gosnmp.GoSNMP, oids []string) {
	r, err := g.Get(oids)
	if ok, _ := checkResult(r, err, false); !ok {
		return
	}
	for _, v := range r.Variables {
		t, val := normalize(v)
		emitVB(normOID(v.Name), t, val)
	}
}

const maxWalkVarbinds = 200000

func doWalk(g *gosnmp.GoSNMP, root string, bulk bool, maxRep int) {
	rootArcs := parseOID(root)
	last := rootArcs
	cur := normOID(root)
	n := 0
	for {
		var r *gosnmp.SnmpPacket
		var err error
		if bulk {
			r, err = g.GetBulk([]string{cur}, 0, uint32(maxRep))
		} else {
			r, err = g.GetNext([]string{cur})
		}
		ok, end := checkResult(r, err, g.Version == gosnmp.Version1)
		if !ok || end {
			return
		}
		if len(r.Variables) == 0 {
			return
		}
		for _, v := range r.Variables {
			switch v.Type {
			case gosnmp.EndOfMibView, gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
				return
			}
			arcs := parseOID(v.Name)
			if !inSubtree(arcs, rootArcs) {
				return
			}
			if cmpOID(arcs, last) <= 0 {
				emitErr("nonIncreasing", fmt.Sprintf("%s after %s", normOID(v.Name), joinOID(last)), nil)
				return
			}
			t, val := normalize(v)
			emitVB(normOID(v.Name), t, val)
			last = arcs
			n++
			if n >= maxWalkVarbinds {
				emitErr("other", "walk limit reached", nil)
				return
			}
		}
		cur = joinOID(last)
	}
}

func joinOID(a []uint64) string {
	s := make([]string, len(a))
	for i, x := range a {
		s[i] = strconv.FormatUint(x, 10)
	}
	return strings.Join(s, ".")
}

func toPDU(v varbindIn) (gosnmp.SnmpPDU, error) {
	p := gosnmp.SnmpPDU{Name: normOID(v.OID)}
	parseU := func(bits int) (uint64, error) { return strconv.ParseUint(v.Value, 10, bits) }
	switch v.Type {
	case "Integer":
		n, err := strconv.ParseInt(v.Value, 10, 32)
		if err != nil {
			return p, err
		}
		p.Type, p.Value = gosnmp.Integer, int(n)
	case "OctetString":
		b, err := hex.DecodeString(v.Value)
		if err != nil {
			return p, err
		}
		p.Type, p.Value = gosnmp.OctetString, b
	case "OID":
		p.Type, p.Value = gosnmp.ObjectIdentifier, normOID(v.Value)
	case "IpAddress":
		p.Type, p.Value = gosnmp.IPAddress, v.Value
	case "Counter32":
		n, err := parseU(32)
		if err != nil {
			return p, err
		}
		p.Type, p.Value = gosnmp.Counter32, uint32(n)
	case "Gauge32":
		n, err := parseU(32)
		if err != nil {
			return p, err
		}
		p.Type, p.Value = gosnmp.Gauge32, uint(n)
	case "TimeTicks":
		n, err := parseU(32)
		if err != nil {
			return p, err
		}
		p.Type, p.Value = gosnmp.TimeTicks, uint32(n)
	case "Counter64":
		n, err := parseU(64)
		if err != nil {
			return p, err
		}
		p.Type, p.Value = gosnmp.Counter64, n
	case "Null":
		p.Type, p.Value = gosnmp.Null, nil
	default:
		return p, fmt.Errorf("gosnmp cannot SET type %s", v.Type)
	}
	return p, nil
}

func doSet(g *gosnmp.GoSNMP, vbs []varbindIn) {
	pdus := make([]gosnmp.SnmpPDU, 0, len(vbs))
	for _, v := range vbs {
		p, err := toPDU(v)
		if err != nil {
			emitErr("other", err.Error(), nil)
			return
		}
		pdus = append(pdus, p)
	}
	r, err := g.Set(pdus)
	if ok, _ := checkResult(r, err, false); !ok {
		return
	}
	for _, v := range r.Variables {
		t, val := normalize(v)
		emitVB(normOID(v.Name), t, val)
	}
}

func main() {
	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "bad request:", err)
		os.Exit(2)
	}
	g, err := newClient(req.Target)
	if err != nil {
		emitErr("other", err.Error(), nil)
		return
	}
	if err := g.Connect(); err != nil {
		c, m := classifyErr(err)
		emitErr(c, m, nil)
		return
	}
	defer g.Conn.Close()
	maxRep := req.MaxRepetitions
	if maxRep <= 0 {
		maxRep = 10
	}
	switch req.Op {
	case "get":
		doGet(g, req.OIDs)
	case "walk":
		doWalk(g, req.Root, false, 0)
	case "bulkwalk":
		if g.Version == gosnmp.Version1 {
			emitErr("other", "GETBULK not supported in SNMPv1", nil)
			return
		}
		doWalk(g, req.Root, true, maxRep)
	case "set":
		doSet(g, req.Varbinds)
	default:
		fmt.Fprintln(os.Stderr, "unknown op", req.Op)
		os.Exit(2)
	}
}
