/**
 * The subgraph endpoint nests entity attributes under `props` ({id, type, props}),
 * but every consumer (EgoGraph, EntityHeader, EvidenceTabs) reads them flat --
 * `n.name`, `edge.confidence`. Flatten once here so those components see the shape
 * they were written against. Structural fields (id/type/labels) are spread last so a
 * property named `type` can never shadow the entity's real type.
 *
 * Kept free of any Vite/axios import so it can be exercised outside the bundler.
 */
function flattenEntity(entity) {
  if (!entity) return entity;
  return { ...(entity.props || {}), ...entity };
}

export function normalizeSubgraph(raw) {
  if (!raw) return raw;
  return {
    ...raw,
    node: flattenEntity(raw.node),
    neighbors: (raw.neighbors || []).map(flattenEntity),
    edges: (raw.edges || []).map(flattenEntity),
  };
}
