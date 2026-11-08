'use strict';
/**
 * Trap / inform receiver (UDP, default 162). Notifications from a configured device's address are
 * recorded and pushed as the value of that device's `snmpTrap` point (a string point, not polled),
 * so they trend and can drive NF alarms/hooks. Notifications from unknown sources are kept in the
 * in-memory log only.
 *
 * SNMPv3: the USM users of all v3 devices are registered. Informs work out of the box (we are the
 * authoritative engine); v3 *traps* need the sender to use our engine ID or net-snmp's per-message
 * localization — see README. v1/v2c communities are accepted from any configured device address.
 */
const snmp = require('net-snmp');
const N = require('../snmp/normalize');
require('../snmp/des').install(snmp);
const { uuidv5 } = require('./store');

const SNMP_TRAP_OID = '1.3.6.1.6.3.1.1.4.1.0';
const SYS_UPTIME = '1.3.6.1.2.1.1.3.0';
const GENERIC = ['coldStart', 'warmStart', 'linkDown', 'linkUp', 'authenticationFailure', 'egpNeighborLoss', 'enterpriseSpecific'];

class TrapReceiver {
  constructor({ engine, port = 162, log }) {
    this.engine = engine;
    this.port = port;
    this.log = log;
    this.receiver = null;
    this.log_ = [];
    this.max = 1000;
    this.counts = { received: 0, matched: 0, unknownSource: 0, errors: 0 };
    this.users = new Set();
  }

  start() {
    return new Promise((resolve, reject) => {
      let settled = false;
      try {
        this.receiver = snmp.createReceiver({ port: this.port, disableAuthorization: true, includeAuthentication: true, transport: 'udp4' }, (err, n) => {
          if (err) {
            this.counts.errors++;
            this.log.debug('trap receive error', { error: err.message });
            return;
          }
          try {
            this.onNotification(n);
          } catch (e) {
            this.counts.errors++;
            this.log.warn('trap handling failed', { error: e.message });
          }
        });
      } catch (e) {
        reject(e);
        return;
      }
      this.syncUsers();
      const sock = this.receiver.listener && this.receiver.listener.sockets ? Object.values(this.receiver.listener.sockets)[0] : null;
      if (sock && sock.once) {
        sock.once('error', (e) => {
          if (!settled) {
            settled = true;
            reject(e);
          }
        });
        sock.once('listening', () => {
          if (!settled) {
            settled = true;
            this.log.info('trap receiver listening', { port: this.port });
            resolve();
          }
        });
        setTimeout(() => {
          if (!settled) {
            settled = true;
            resolve();
          }
        }, 500);
      } else resolve();
    });
  }

  stop() {
    return new Promise((resolve) => {
      if (!this.receiver) return resolve();
      try {
        this.receiver.close(() => resolve());
      } catch {
        resolve();
      }
      setTimeout(resolve, 200);
      this.receiver = null;
    });
  }

  /** Register USM users of v3 devices. */
  syncUsers() {
    if (!this.receiver) return;
    const auth = this.receiver.getAuthorizer();
    for (const d of Object.values(this.engine.store.devices)) {
      if (d.version !== '3' || !d.user || this.users.has(d.user)) continue;
      const authP = (d.authProtocol || 'none').toLowerCase();
      const privP = (d.privProtocol || 'none').toLowerCase();
      const user = { name: d.user, level: snmp.SecurityLevel.noAuthNoPriv };
      if (authP !== 'none') {
        user.level = privP !== 'none' ? snmp.SecurityLevel.authPriv : snmp.SecurityLevel.authNoPriv;
        user.authProtocol = snmp.AuthProtocols[authP];
        user.authKey = d.authKey;
        if (privP !== 'none') {
          user.privProtocol = snmp.PrivProtocols[privP];
          user.privKey = d.privKey;
        }
      }
      try {
        auth.addUser(user);
        this.users.add(d.user);
      } catch (e) {
        this.log.warn('could not register trap user', { user: d.user, error: e.message });
      }
    }
  }

  onNotification(n) {
    this.counts.received++;
    const pdu = n.pdu || {};
    const from = (n.rinfo && n.rinfo.address) || '';
    const vbs = (pdu.varbinds || []).map((vb) => {
      try {
        return N.fromVarbind(vb);
      } catch {
        return { oid: String(vb.oid), type: 'Unknown', value: '' };
      }
    });
    let trapOid = '';
    let kind = 'trap';
    if (pdu.type === snmp.PduType.Trap) {
      // SNMPv1: enterprise + generic/specific
      const g = Number(pdu.generic);
      trapOid = g === 6 ? `${pdu.enterprise}.0.${pdu.specific}` : `1.3.6.1.6.3.1.1.5.${g + 1}`;
      kind = `v1 ${GENERIC[g] || g}`;
    } else {
      const t = vbs.find((v) => v.oid === SNMP_TRAP_OID);
      trapOid = t ? t.value : '';
      kind = pdu.type === snmp.PduType.InformRequest ? 'inform' : 'trap';
    }
    const device = Object.values(this.engine.store.devices).find((d) => d.host === from);
    const rec = {
      ts: Date.now(),
      from,
      device: device ? device.name : null,
      deviceUuid: device ? device.uuid : null,
      kind,
      trapOid,
      community: n.pdu && n.pdu.community ? undefined : undefined,
      user: n.user ? n.user.name : undefined,
      varbinds: vbs.filter((v) => v.oid !== SNMP_TRAP_OID && v.oid !== SYS_UPTIME).map((v) => ({ oid: v.oid, type: v.type, value: v.type === 'OctetString' ? N.hexToText(v.value) ?? v.value : v.value })),
    };
    this.log_.push(rec);
    if (this.log_.length > this.max) this.log_.shift();
    if (!device) {
      this.counts.unknownSource++;
      return;
    }
    this.counts.matched++;
    const summary = `${trapOid}${rec.varbinds.length ? ' ' + rec.varbinds.map((v) => `${v.oid}=${v.value}`).join(' ').slice(0, 900) : ''}`;
    this.engine.recordTrap(device.uuid, rec, summary).catch((e) => this.log.warn('trap publish failed', { error: e.message }));
  }

  recent(limit = 100) {
    return this.log_.slice(-limit).reverse();
  }

  status() {
    return { port: this.port, listening: !!this.receiver, counts: this.counts, users: [...this.users] };
  }
}

function trapPointUuid(deviceUuid) {
  return uuidv5(`${deviceUuid}/trap`);
}

module.exports = { TrapReceiver, trapPointUuid };
