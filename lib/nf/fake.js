'use strict';
/** In-memory NF adapter for tests: records upserts, deletes and pushed data. */
function create() {
  const points = new Map();
  const data = [];
  const removed = [];
  return {
    points: {
      async upsert(pts) { for (const p of pts) points.set(p.uuid, Object.assign({}, points.get(p.uuid) || {}, p)); return pts.map((p) => ({ uuid: p.uuid })); },
      async listLayer(layer) { return [...points.values()].filter((p) => p.layer === layer); },
      async remove(uuids) { for (const u of uuids) { points.delete(u); removed.push(u); } },
      async writeData(layer, items) { for (const i of items) data.push(Object.assign({ layer }, i)); },
    },
    _points: points,
    _data: data,
    _removed: removed,
  };
}
module.exports = { create };
