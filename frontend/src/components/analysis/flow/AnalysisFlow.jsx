/* eslint-disable id-length */
import React from "react";
import PropTypes from "prop-types";
import ReactFlow, {
  Controls,
  MiniMap,
  MarkerType,
  useNodesState,
  useEdgesState,
} from "reactflow";
import "reactflow/dist/style.css";

import CustomAnalysisNode from "./CustomAnalysisNode";
import CustomJobNode from "./CustomJobNode";
import { calculateNodesAndEdges } from "./utils";

// Important! This must be defined outside of the component
const nodeTypes = {
  analysisNode: CustomAnalysisNode,
  jobNode: CustomJobNode,
};

const defaultEdgeOptions = {
  style: { strokeWidth: 2 },
  type: "step",
  markerEnd: {
    type: MarkerType.ArrowClosed,
  },
};

export function AnalysisFlow({ analysisTree, analysisId, refetchTree }) {
  console.debug("AnalysisFlow rendered");

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  React.useEffect(() => {
    const [initialNodes, initialEdges] = calculateNodesAndEdges(
      analysisTree,
      analysisId,
      refetchTree,
    );
    setNodes(initialNodes);
    setEdges(initialEdges);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisTree]);

  return (
    <div className="bg-body" style={{ width: "100vw", height: "65vh" }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        defaultEdgeOptions={defaultEdgeOptions}
        defaultViewport={{ x: 0, y: 0, zoom: 1.2 }}
        nodeTypes={nodeTypes}
        deleteKeyCode={null}
        preventScrolling={false}
        zoomOnDoubleClick={false}
      >
        <MiniMap pannable />
        <Controls />
      </ReactFlow>
    </div>
  );
}

AnalysisFlow.propTypes = {
  analysisId: PropTypes.number.isRequired,
  analysisTree: PropTypes.object.isRequired,
  refetchTree: PropTypes.func.isRequired,
};
