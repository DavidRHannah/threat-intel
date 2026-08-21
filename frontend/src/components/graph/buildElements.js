/**
 * Builds the cytoscape element list for an ego graph.
 *
 * Extracted from EgoGraph so it can be exercised directly against real API payloads.
 * cytoscape THROWS on an edge whose source/target is not a known node, and a throw
 * during render unmounts the whole app -- so every edge is checked against the node
 * set before it is emitted.
 *
 * `hideTypes` drops neighbors of the given type(s) before the node set is built, so
 * edges pointing at a hidden neighbor are dropped for free by the existing
 * dangling-edge filter below -- the central node is never hidden even if its own type
 * is in the list, since that's the entity actually being viewed.
 */
export function buildElements(data, { hideTypes = [] } = {}) {
  if (!data) return [];

  const { node: centralNode, neighbors = [], edges = [] } = data;
  if (!centralNode?.id) return [];

  const els = [
    {
      data: {
        id: centralNode.id,
        label: centralNode.cve_id || centralNode.name || centralNode.cwe_id
          || centralNode.title || centralNode.id,
        type: centralNode.type,
      },
    },
  ];

  neighbors.forEach((n) => {
    if (!n?.id) return;
    if (hideTypes.includes(n.type)) return;
    els.push({
      data: {
        id: n.id,
        label: n.name || n.cve_id || n.value || n.title || n.cwe_id || n.id,
        type: n.type,
      },
    });
  });

  const nodeIds = new Set(els.map((el) => el.data.id));
  edges.forEach((e, idx) => {
    if (!nodeIds.has(e.source) || !nodeIds.has(e.target)) return;
    els.push({
      data: {
        id: `edge-${idx}`,
        source: e.source,
        target: e.target,
        label: e.type,
        confidence: e.confidence ?? 0,
        origin: (Array.isArray(e.origin) ? e.origin[0] : e.origin) || 'inferred',
      },
    });
  });

  return els;
}
