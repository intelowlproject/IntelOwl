import { getLayoutedElements } from "../../common/flows/getLayoutedElements";
import { JobFinalStatuses } from "../../../constants/jobConst";
import { DataModelTagsIcons } from "../../../constants/dataModelConst";

/* eslint-disable id-length */
function addJobNode(
  nodes,
  job,
  investigationId,
  refetchTree,
  refetchInvestigation,
  isFirstLevel,
) {
  // engine fields
  const engineFields = {
    evaluation: job?.evaluation || "",
    reliability: job?.reliability,
    tags: job?.tags || [],
  };
  if (engineFields.tags.length > 0) {
    const customTags = [];
    const tags = [];
    engineFields.tags.forEach((tag) => {
      if (Object.keys(DataModelTagsIcons).includes(tag)) {
        tags.push(tag);
      } else {
        customTags.push(tag);
      }
    });
    if (customTags.length > 0) tags.push(customTags.toString());
    engineFields.tags = tags;
  }

  // optional fields
  if (job.country) engineFields.country = job.country;
  if (job.isp) engineFields.isp = job.isp;
  if (job.mimetype) engineFields.mimetype = job.mimetype;

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
      is_sample: job.is_sample,
      refetchTree,
      refetchInvestigation,
      isFirstLevel: isFirstLevel || false,
      created: job.received_request_time,
      engineFields,
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
      300,
      60,
      150,
      80,
    );
    return [
      initialNode.concat(layoutedNodes),
      initialEdges.concat(layoutedEdges),
    ];
  }

  return [initialNode, initialEdges];
}
