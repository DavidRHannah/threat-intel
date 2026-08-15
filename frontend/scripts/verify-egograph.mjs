import cytoscape from 'cytoscape';
import fs from 'fs';
import { normalizeSubgraph } from '../src/api/normalize.js';
import { buildElements } from '../src/components/graph/buildElements.js';

const raw = JSON.parse(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')).body);
const data = normalizeSubgraph(raw);

console.log('node.id      =', data.node.id);
console.log('node.cve_id  =', data.node.cve_id, '(flattened from props)');
console.log('neighbor[0]  =', JSON.stringify({ id: data.neighbors[0]?.id, type: data.neighbors[0]?.type, cwe_id: data.neighbors[0]?.cwe_id }));

const els = buildElements(data);
console.log('elements built:', els.length, '| edges kept:', els.filter(e => e.data.source).length, 'of', data.edges.length);
try {
  const cy = cytoscape({ headless: true, elements: els });
  console.log('RESULT: cytoscape OK — nodes:', cy.nodes().length, 'edges:', cy.edges().length);
  console.log('labels:', cy.nodes().map(n => n.data('label')).join(', '));
} catch (err) {
  console.log('RESULT: THREW ->', err.message);
  process.exit(1);
}
