// Minimal standalone SNMP agent for the e2e spike (net-snmp), UDP 161, community public/private.
const snmp = require('net-snmp');
const agent = snmp.createAgent({ port: 161, accessControlModelType: snmp.AccessControlModelType.None }, (e) => e && console.error(e));
agent.getAuthorizer().addCommunity('public');
agent.getAuthorizer().addCommunity('private');
const mib = agent.getMib();
const ENT = '1.3.6.1.4.1.55555';
const sc = (name, oid, type, value, rw) => { mib.registerProvider({ name, type: snmp.MibProviderType.Scalar, oid, scalarType: type, maxAccess: snmp.MaxAccess[rw ? 'read-write' : 'read-only'] }); mib.setScalarValue(name, value); };
sc('sysDescr', '1.3.6.1.2.1.1.1', snmp.ObjectType.OctetString, 'Spike UPS');
sc('sysObjectID', '1.3.6.1.2.1.1.2', snmp.ObjectType.OID, '1.3.6.1.2.1.33');
sc('sysUpTime', '1.3.6.1.2.1.1.3', snmp.ObjectType.TimeTicks, 100);
sc('sysName', '1.3.6.1.2.1.1.5', snmp.ObjectType.OctetString, 'spike-ups');
sc('upsIdentModel', '1.3.6.1.2.1.33.1.1.2', snmp.ObjectType.OctetString, 'SpikeUPS 3000');
sc('upsEstimatedChargeRemaining', '1.3.6.1.2.1.33.1.2.4', snmp.ObjectType.Integer, 87);
sc('upsBatteryVoltage', '1.3.6.1.2.1.33.1.2.5', snmp.ObjectType.Integer, 545);
sc('upsBatteryTemperature', '1.3.6.1.2.1.33.1.2.7', snmp.ObjectType.Integer, 25);
setInterval(() => { mib.setScalarValue('upsEstimatedChargeRemaining', 50 + Math.floor((Date.now() / 1000) % 50)); }, 1000);
console.log('spike agent up');
