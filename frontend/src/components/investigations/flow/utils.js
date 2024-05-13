import dagre from "@dagrejs/dagre";
import { JobFinalStatuses } from "../../../constants/jobConst";

/* eslint-disable id-length */
function addJobNode(
  nodes,
  job,
  investigationId,
  refetchTree,
  refetchInvestigation,
  isFirstLevel,
) {
  nodes.push({
    id: `job-${job.pk}`,
    data: {
      id: job.pk,
      label: `job #${job.pk}`,
      name: job.analyzed_object_name,
      playbook: job.playbook,
      investigation: investigationId,
      children: job.children || [],
      status: job.status,
      refetchTree,
      refetchInvestigation,
      isFirstLevel: isFirstLevel || false,
      created: job.received_request_time,
    },
    type: "jobNode",
  });

  // recursive call if there are children
  if (job.children) {
    job.children.forEach((child) => {
      addJobNode(nodes, child, investigationId, refetchTree);
    });
  }
}

function addEdge(edges, job, parentType, parentId) {
  edges.push({
    id: `edge-${parentType}${parentId}-job${job.pk}`,
    source: `${parentType}-${parentId}`,
    target: `job-${job.pk}`,
    animated: !Object.values(JobFinalStatuses).includes(job.status),
  });

  // recursive call if there are children
  if (job.children) {
    job.children.forEach((child) => {
      addEdge(edges, child, "job", job.pk);
    });
  }
}

function getLayoutedElements(nodes, edges) {
  // needed for graph layout
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  const nodeWidth = 300;
  const nodeHeight = 60;

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
      x: nodeWithPosition.x - nodeWidth / 2 + 150,
      y: nodeWithPosition.y - nodeHeight / 2 + 70,
    };
    return node;
  });
  return { nodes, edges };
}

export function getNodesAndEdges(
  investigationTree,
  investigationId,
  refetchTree,
  refetchInvestigation,
) {
  // investigation node
  const initialNode = [
    {
      id: `investigation-${investigationId}`,
      position: { x: 2, y: 2 },
      data: {
        id: investigationId,
        label: investigationTree.name,
        refetchTree,
        refetchInvestigation,
      },
      type: "investigationNode",
      draggable: false,
    },
  ];
  // jobs nodes
  const jobsNodes = [];

  // edges
  const initialEdges = [];
  const jobsEdges = [];

  if (investigationTree.jobs.length) {
    investigationTree.jobs.forEach((job) => {
      addJobNode(
        jobsNodes,
        job,
        investigationId,
        refetchTree,
        refetchInvestigation,
        true,
      );
      addEdge(jobsEdges, job, "investigation", investigationId);
    });
  }

  if (jobsEdges.length) {
    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
      jobsNodes,
      jobsEdges,
    );
    return [
      initialNode.concat(layoutedNodes),
      initialEdges.concat(layoutedEdges),
    ];
  }

  return [initialNode, initialEdges];
}
