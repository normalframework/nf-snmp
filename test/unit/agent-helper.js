'use strict';
// In-process net-snmp agent for unit tests (a real UDP agent on 127.0.0.1).
const snmp = require('net-snmp');
function startAgent({ port = 0, scalars = {}, onSet } = {}) {
  return new Promise((resolve) => {
    const agent = snmp.createAgent({ port, address: '127.0.0.1', disableAuthorization: false, accessControlModelType: snmp.AccessControlModelType.None }, () => {});
    const auth = agent.getAuthorizer();
    auth.addCommunity('public');
    auth.addUser({ name: 'shaaes', level: snmp.SecurityLevel.authPriv, authProtocol: snmp.AuthProtocols.sha, authKey: 'authpass123', privProtocol: snmp.PrivProtocols.aes, privKey: 'privpass123' });
    const mib = agent.getMib();
    let n = 0;
    for (const [oid, def] of Object.entries(scalars)) {
      const base = oid.replace(/\.0$/, '');
      const name = 'p' + n++;
      mib.registerProvider({ name, type: snmp.MibProviderType.Scalar, oid: base, scalarType: def.type, maxAccess: snmp.MaxAccess['read-write'],
        handler: (mibRequest) => { if (onSet && mibRequest.operation === snmp.PduType.SetRequest) onSet(oid, mibRequest); mibRequest.done(); } });
      mib.setScalarValue(name, def.value);
    }
    setTimeout(() => {
      const addr = agent.listener.subscribers ? null : null; // net-snmp doesn't expose port; use fixed
      resolve({ agent, mib, port, close: () => agent.close() });
    }, 50);
  });
}
module.exports = { startAgent };
