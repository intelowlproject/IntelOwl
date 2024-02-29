import { JobFinalStatuses } from "../../../constants/jobConst";

/* eslint-disable id-length */
function addJobNode(nodes, job, analysisId, position, refetchTree) {
  nodes.push({
    id: `job-${job.pk}`,
    position,
    data: {
      id: job.pk,
      label: `job #${job.pk}`,
      name: job.isSample ? job.file_name : job.observable_name,
      playbook: job.playbook,
      analysis: analysisId,
      children: job.children || [],
      status: job.status,
      refetchTree,
    },
    type: "jobNode",
  });

  // recursive call if there are children
  if (job.children) {
    const xPosition = nodes[0].position.x + 310;
    const numChildren = job.children.length;

    job.children.forEach((child, index) => {
      if (numChildren === 1)
        addJobNode(
          nodes,
          child,
          analysisId,
          { x: xPosition, y: position.y },
          refetchTree,
        );
      else {
        const parentYPosition = position.y;
        const yPosition = (index + 1) * parentYPosition;
        addJobNode(
          nodes,
          child,
          analysisId,
          { x: xPosition, y: yPosition },
          refetchTree,
        );
      }
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

export function calculateNodesAndEdges(analysisTree, analysisId, refetchTree) {
  // analysis node (custom node)
  const initialNode = [
    {
      id: `analysis-${analysisId}`,
      position: { x: 2, y: 2 },
      data: {
        id: analysisId,
        label: analysisTree.name,
        refetchTree,
      },
      type: "analysisNode",
      draggable: false,
    },
  ];
  // jobs nodes
  const jobsNodes = [];
  let yPosition = initialNode[0].position.y;

  // edges
  const initialEdges = [];
  const jobsEdges = [];

  if (analysisTree.jobs.length) {
    analysisTree.jobs.forEach((job) => {
      yPosition += 120;
      addJobNode(
        jobsNodes,
        job,
        analysisId,
        { x: initialNode[0].position.x + 170, y: yPosition },
        refetchTree,
      );
      addEdge(jobsEdges, job, "analysis", analysisId);
    });
  }

  return [initialNode.concat(jobsNodes), initialEdges.concat(jobsEdges)];
}
