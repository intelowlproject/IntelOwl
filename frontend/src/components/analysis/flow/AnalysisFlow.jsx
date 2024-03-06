/* eslint-disable id-length */
import React from "react";
import PropTypes from "prop-types";
import ReactFlow, {
  Controls,
  MiniMap,
  MarkerType,
  useNodesState,
  useEdgesState,
  Panel,
} from "reactflow";
import "reactflow/dist/style.css";

import CustomAnalysisNode from "./CustomAnalysisNode";
import CustomJobNode from "./CustomJobNode";
import { getNodesAndEdges } from "./utils";

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

export function AnalysisFlow({
  analysisTree,
  analysisId,
  refetchTree,
  refetchAnalysis,
}) {
  console.debug("AnalysisFlow rendered");

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  React.useEffect(() => {
    const [initialNodes, initialEdges] = getNodesAndEdges(
      analysisTree,
      analysisId,
      refetchTree,
      refetchAnalysis,
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
        <Panel position="top-right">
          <div
            className="px-3 py-1 bg-dark d-flex flex-column"
            style={{
              minWidth: "230px",
            }}
          >
            Edges:
            <div className="d-flex justify-content-between">
              <hr
                style={{
                  width: "45px",
                  borderTop: "3px solid white",
                  opacity: 1,
                }}
              />
              <span>job is concluded</span>
            </div>
            <div className="d-flex justify-content-between">
              <hr
                className="bg-dark"
                style={{
                  width: "45px",
                  borderTop: "3px dashed white",
                  borderStyle: "dashed",
                  opacity: 1,
                }}
              />
              <span>job is running</span>
            </div>
          </div>
        </Panel>
      </ReactFlow>
    </div>
  );
}

AnalysisFlow.propTypes = {
  analysisId: PropTypes.number.isRequired,
  analysisTree: PropTypes.object.isRequired,
  refetchTree: PropTypes.func.isRequired,
  refetchAnalysis: PropTypes.func.isRequired,
};
