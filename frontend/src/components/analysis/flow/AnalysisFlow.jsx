/* eslint-disable id-length */
import React from "react";
import PropTypes from "prop-types";
import ReactFlow, {
  Controls,
  applyEdgeChanges,
  applyNodeChanges,
  MiniMap,
  MarkerType,
} from "reactflow";
import "reactflow/dist/style.css";

import AnalysisNode from "./AnalysisNode";

const defaultEdgeOptions = {
  style: { strokeWidth: 2 },
  type: "step",
  markerEnd: {
    type: MarkerType.ArrowClosed,
  },
};

// Important! This must be defined outside of the component
const nodeTypes = {
  "analysis-node": AnalysisNode,
};

export function AnalysisFlow({ analysis }) {
  console.debug("AnalysisFlow rendered");

  // analysis node (custom node)
  const initialNode = [
    {
      id: `${analysis.id}`,
      position: { x: 2, y: 2 },
      data: { label: analysis.name },
      type: "analysis-node",
      draggable: false,
    },
  ];
  const initialEdges = [];

  // jobs nodes
  const jobsNodes = [];
  const jobsEdges = [];
  let yPosition = 0;

  if (analysis.total_jobs) {
    analysis.jobs.forEach((jobId) => {
      console.debug(jobId);
      yPosition += 70;

      jobsNodes.push({
        id: `job-${jobId}`,
        position: { x: 102, y: yPosition },
        data: { label: `job #${jobId}` },
        targetPosition: "left",
        sourcePosition: "right",
        style: {
          background: "#2f515e",
          color: "#D6D5E6",
          border: "1px solid #5593ab",
        },
      });

      jobsEdges.push({
        id: `edge-analysis${analysis.id}-job${jobId}`,
        source: `${analysis.id}`,
        target: `job-${jobId}`,
      });
    });
  }

  const [nodes, setNodes] = React.useState(initialNode.concat(jobsNodes));
  const [edges, setEdges] = React.useState(initialEdges.concat(jobsEdges));

  const onNodesChange = React.useCallback(
    (changes) => setNodes((nds) => applyNodeChanges(changes, nds)),
    [],
  );
  const onEdgesChange = React.useCallback(
    (changes) => setEdges((eds) => applyEdgeChanges(changes, eds)),
    [],
  );

  return (
    <div className="bg-body" style={{ width: "100vw", height: "65vh" }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        defaultEdgeOptions={defaultEdgeOptions}
        defaultViewport={{ x: 0, y: 0, zoom: 1.3 }}
        nodeTypes={nodeTypes}
        deleteKeyCode={null}
        preventScrolling={false}
      >
        <MiniMap pannable />
        <Controls />
      </ReactFlow>
    </div>
  );
}

AnalysisFlow.propTypes = {
  analysis: PropTypes.object.isRequired,
};
