import dagre from "@dagrejs/dagre";

/* eslint-disable id-length */
export function getLayoutedElements(
  nodes,
  edges,
  nodeWidth,
  nodeHeight,
  deltaX,
  deltaY,
) {
  // needed for graph layout
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  dagreGraph.setGraph({ rankdir: "LR" });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  nodes.forEach((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    // eslint-disable-next-line no-param-reassign
    node.position = {
      x: nodeWithPosition.x - nodeWidth / 2 + deltaX,
      y: nodeWithPosition.y - nodeHeight / 2 + deltaY,
    };
    return node;
  });
  return { nodes, edges };
}
