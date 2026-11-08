import { describe, it, expect } from 'vitest';
import dec from '../../lib/profiles/decode.js';
import disc from '../../lib/engine/discovery.js';
const { decode, encode } = dec;
const hex = (s) => Buffer.from(s).toString('hex');
const H = (m) => (oid) => m[oid];

describe('decode', () => {
  it('scales, offsets, display hints', () => {
    expect(decode({ type: 'Gauge32', value: '243' }, { decode: { scale: 0.1 } })).toBe(24.3);
    expect(decode({ type: 'Integer', value: '-15' }, { decode: { scale: 0.1 } })).toBe(-1.5);
    expect(decode({ type: 'Integer', value: '700' }, { decode: { displayHint: 'd-2' } })).toBe(7);
    expect(decode({ type: 'Integer', value: '20' }, { decode: { scale: 1.8, offset: 32 } })).toBe(68);
  });
  it('TimeTicks to seconds unless scaled or raw', () => {
    expect(decode({ type: 'TimeTicks', value: '12345' }, { decode: {} })).toBe(123.45);
    expect(decode({ type: 'TimeTicks', value: '12345' }, { decode: { rawTicks: true } })).toBe(12345);
  });
  it('decimal digits from helper OID (Raritan)', () => {
    expect(decode({ type: 'Gauge32', value: '1234' }, { decode: { decimalDigitsOid: '1.2.3' } }, H({ '1.2.3': { type: 'Gauge32', value: '3' } }))).toBe(1.234);
    expect(() => decode({ type: 'Gauge32', value: '1' }, { decode: { decimalDigitsOid: '1.2.3' } })).toThrow(/decimal digits/);
  });
  it('ENTITY-SENSOR scale/precision/status (RFC 3433)', () => {
    const es = { scaleOid: 's', precisionOid: 'p', statusOid: 'o' };
    // milli (8) volts, precision 0: 12000 mV = 12 V; units(9) celsius precision 1: 255 = 25.5
    expect(decode({ type: 'Integer', value: '12000' }, { decode: { entitySensor: es } }, H({ s: { value: '8' }, p: { value: '0' }, o: { value: '1' } }))).toBe(12);
    expect(decode({ type: 'Integer', value: '255' }, { decode: { entitySensor: es } }, H({ s: { value: '9' }, p: { value: '1' }, o: { value: '1' } }))).toBe(25.5);
    expect(() => decode({ type: 'Integer', value: '1' }, { decode: { entitySensor: es } }, H({ s: { value: '9' }, p: { value: '0' }, o: { value: '2' } }))).toThrow(/OperStatus/);
    expect(() => decode({ type: 'Integer', value: '1000000000' }, { decode: { entitySensor: es } }, H({ s: { value: '9' }, p: { value: '0' }, o: { value: '1' } }))).toThrow(/out of range/);
  });
  it('strings, regex floats, sentinels, counters', () => {
    expect(decode({ type: 'OctetString', value: hex('Rack A') }, { decode: {} })).toBe('Rack A');
    expect(decode({ type: 'OctetString', value: hex('23.5 C') }, { decode: { regex: '/(-?[0-9.]+)/' } })).toBe(23.5);
    expect(decode({ type: 'OctetString', value: hex(' 42 ') }, { decode: { type: 'number' } })).toBe(42);
    expect(() => decode({ type: 'Gauge32', value: '255' }, { decode: { sentinels: ['255'] } })).toThrow(/sentinel/);
    expect(decode({ type: 'Counter64', value: '18446744073709551615' }, { decode: {} })).toBe(18446744073709552000);
    expect(decode({ type: 'OctetString', value: '00ff10' }, { decode: {} })).toBe('00ff10');
  });
  it('encode inverts decode for writes', () => {
    expect(encode(23.5, { oid: '1.1', setType: 'Integer', decode: { scale: 0.1 } })).toEqual({ oid: '1.1', type: 'Integer', value: '235' });
    expect(encode('off', { oid: '1.1', setType: 'Integer', decode: { enum: { 0: 'off', 1: 'on' } } })).toEqual({ oid: '1.1', type: 'Integer', value: '0' });
    expect(encode(1.5, { oid: '1.1', setType: 'Gauge32', decode: { decimalDigitsOid: 'd' } }, H({ d: { value: '2' } }))).toEqual({ oid: '1.1', type: 'Gauge32', value: '150' });
    expect(() => encode('abc', { oid: '1.1', decode: {} })).toThrow();
  });
});

describe('discovery host expansion', () => {
  const { expandHosts } = disc;
  it('expands CIDR without network/broadcast, ranges and names', () => {
    expect(expandHosts('10.0.0.0/30')).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(expandHosts(['10.0.0.8-10', 'ups1.local'])).toEqual(['10.0.0.8', '10.0.0.9', '10.0.0.10', 'ups1.local']);
    expect(expandHosts('10.0.0.254-10.0.1.1')).toEqual(['10.0.0.254', '10.0.0.255', '10.0.1.0', '10.0.1.1']);
    expect(expandHosts('10.0.0.5/32')).toEqual(['10.0.0.5']);
  });
  it('refuses huge or malformed specs', () => {
    expect(() => expandHosts('10.0.0.0/8')).toThrow(/prefix/);
    expect(() => expandHosts('10.0.0.0/20')).toThrow(/more than 1024/);
    expect(() => expandHosts('10.0.0.1;rm')).toThrow(/bad host/);
  });
});
