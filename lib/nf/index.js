'use strict';
/**
 * The only module that talks to NF. `http` is an axios-like client ({get, post, delete} returning
 * {data}); inside NF it is sdk.http (base URL + auth already configured).
 *
 * REST paths come from the google.api.http annotations in gobac
 * src/proto/normalgw/hpl/v1/point.proto.
 */
const EP = {
  POINT_QUERY: '/api/v1/point/query',
  POINTS_UPDATE: '/api/v1/point/points',
  POINTS_DELETE: '/api/v1/point/points',
  POINTS_BY_ID: '/api/v1/point/points-id',
  DATA_BATCH: '/api/v1/points/data',
  DATA_ONE: '/api/v1/point/data',
};

/** @param {{http: any, log?: any, chunk?: number}} opts */
function create(opts) {
  const http = opts.http;
  const chunk = opts.chunk || 250;

  /**
   * @param {{uuid: string, layer: string, name?: string, parentUuid?: string, periodSeconds?: number,
   *   attrs?: Record<string,string>, displayUnits?: string, hplDriver?: string, description?: string,
   *   protocolId?: string, pointType?: string, parentName?: string}[]} points
   */
  async function upsert(points) {
    const results = [];
    for (let i = 0; i < points.length; i += chunk) {
      const body = {
        isAsync: false,
        points: points.slice(i, i + chunk).map((p) => {
          const o = { uuid: p.uuid, layer: p.layer, attrs: stringify(p.attrs || {}) };
          if (p.name !== undefined) o.name = p.name;
          if (p.parentUuid) o.parentUuid = p.parentUuid;
          if (p.parentName) o.parentName = p.parentName;
          if (p.periodSeconds !== undefined) o.period = `${Math.max(0, Math.round(p.periodSeconds))}s`;
          if (p.displayUnits) o.displayUnits = p.displayUnits;
          if (p.hplDriver) o.hplDriver = p.hplDriver;
          if (p.protocolId) o.protocolId = p.protocolId;
          if (p.description) o.description = p.description;
          o.pointType = p.pointType || 'POINT';
          return o;
        }),
      };
      const res = await http.post(EP.POINTS_UPDATE, body);
      results.push(...(((res && res.data) || {}).results || []));
    }
    return results;
  }

  /** All points in a layer (uuid + attrs of that layer). */
  async function listLayer(layer) {
    const out = [];
    let offset = 0;
    for (;;) {
      const res = await http.post(EP.POINT_QUERY, { layer, pageOffset: offset, pageSize: 500 });
      const pts = (res.data && res.data.points) || [];
      out.push(...pts);
      offset += pts.length;
      const total = Number((res.data && res.data.totalCount) || 0);
      if (!pts.length || offset >= total) break;
    }
    return out;
  }

  /** @param {string[]} uuids */
  async function remove(uuids) {
    for (let i = 0; i < uuids.length; i += chunk) {
      await http.delete(EP.POINTS_DELETE, { data: { uuids: uuids.slice(i, i + chunk) } });
    }
  }

  /**
   * Push values for points we own (traps). AddData batch endpoint (NF >= 3.10.5), else per point.
   * @param {string} layer @param {{uuid: string, values: any[]}[]} items hpl Value JSON
   */
  async function writeData(layer, items) {
    try {
      await http.post(EP.DATA_BATCH, { layer, isAsync: false, points: items.map((i) => ({ uuid: i.uuid, values: i.values, errors: i.errors })) });
    } catch (e) {
      const st = e && e.response && e.response.status;
      if (st !== 404 && st !== 405 && st !== 501) throw e;
      for (const i of items) await http.post(EP.DATA_ONE, { uuid: i.uuid, layer, values: i.values, errors: i.errors });
    }
  }

  return { points: { upsert, listLayer, remove, writeData } };
}

function stringify(attrs) {
  const o = {};
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) o[k] = String(v);
  return o;
}

module.exports = { create, EP };
