/* eslint-disable id-length */
import React from "react";
import PropTypes from "prop-types";
import ReactFlow, { MarkerType, useReactFlow, useNodesState } from "reactflow";
import "reactflow/dist/style.css";

import CustomJobPipelineNode from "./CustomJobPipelineNode";
import { getNodes } from "./utils";

// Important! This must be defined outside of the component
const nodeTypes = {
  jobPipelineNode: CustomJobPipelineNode,
};

const defaultEdgeOptions = {
  style: { strokeWidth: 3 },
  type: "step",
  markerEnd: {
    type: MarkerType.ArrowClosed,
  },
};

const edges = [
  {
    id: `edge-analyzers-connectors`,
    source: `isRunningJob-analyzers`,
    target: `isRunningJob-connectors`,
  },
  {
    id: `edge-connectors-pivots`,
    source: `isRunningJob-connectors`,
    target: `isRunningJob-pivots`,
  },
  {
    id: `edge-pivots-visualizers`,
    source: `isRunningJob-pivots`,
    target: `isRunningJob-visualizers`,
  },
];

export function JobIsRunningFlow({ job }) {
  const initialNodes = getNodes(job, true);
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);

  React.useEffect(() => {
    const updatedNodes = getNodes(job);
    setNodes(updatedNodes);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job]);

  const reactFlowInstance = useReactFlow();
  // this is necessary to properly resize the flow in Google Chrome
  React.useEffect(() => {
    console.debug("JobIsRunningFlow - set fitView property");
    setTimeout(() => reactFlowInstance.fitView(), 0);
  });

  return (
    <div
      id="JobPipelineFlow"
      className="bg-body"
      style={{ width: "2000px", height: "90px" }}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        defaultEdgeOptions={defaultEdgeOptions}
        defaultViewport={{ x: 0, y: 0, zoom: 1.2 }}
        nodeTypes={nodeTypes}
        deleteKeyCode={null}
        preventScrolling={false}
        zoomOnDoubleClick={false}
        panOnDrag={false}
        elementsSelectable={false}
      />
    </div>
  );
}

JobIsRunningFlow.propTypes = {
  job: PropTypes.object.isRequired,
};
