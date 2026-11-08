import { describe, it, expect } from 'vitest';
import des from '../../lib/snmp/des.js';
const h = (s) => Buffer.from(s, 'hex');
describe('pure-JS DES', () => {
  it('matches FIPS / classic test vectors', () => {
    expect(des.encryptBlock(h('133457799BBCDFF1'), h('0123456789ABCDEF')).toString('hex')).toBe('85e813540f0ab405');
    expect(des.decryptBlock(h('133457799BBCDFF1'), h('85E813540F0AB405')).toString('hex')).toBe('0123456789abcdef');
    // NBS validation set (variable plaintext, key 0101010101010101)
    expect(des.encryptBlock(h('0101010101010101'), h('8000000000000000')).toString('hex')).toBe('95f8a5e5dd31d900');
    expect(des.encryptBlock(h('0E329232EA6D0D73'), h('8787878787878787')).toString('hex')).toBe('0000000000000000');
  });
  it('CBC round-trips and chains', () => {
    const key = h('0123456789abcdef');
    const iv = h('1234567890abcdef');
    const pt = Buffer.from('Now is the time for all ');
    const ct = des.cbc(true, key, iv, pt);
    // FIPS 81 CBC example
    expect(ct.toString('hex')).toBe('e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6');
    expect(des.cbc(false, key, iv, ct).toString()).toBe('Now is the time for all ');
  });
});
