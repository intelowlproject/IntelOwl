/* eslint-disable id-length */
import React from "react";
import PropTypes from "prop-types";
import ReactFlow, { Controls, useNodesState, useEdgesState } from "reactflow";
import "reactflow/dist/style.css";

import CustomPlaybookNode from "./CustomPlaybookNode";
import CustomPivotNode from "./CustomPivotNode";
import { getNodesAndEdges } from "./utils";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";

// Important! This must be defined outside of the component
const nodeTypes = {
  playbookNode: CustomPlaybookNode,
  pivotNode: CustomPivotNode,
};

const defaultEdgeOptions = {
  style: { strokeWidth: 3 },
  type: "step",
};

export function PlaybookFlows({ playbook }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  // API/ store
  const [pivotsLoading, pivotStored, playbooksLoading, playbooksStored] =
    usePluginConfigurationStore((state) => [
      state.pivotsLoading,
      state.pivots,
      state.playbooksLoading,
      state.playbooks,
    ]);

  React.useEffect(() => {
    if (!pivotsLoading && !playbooksLoading) {
      const [initialNodes, initialEdges] = getNodesAndEdges(
        playbook,
        pivotStored,
        playbooksStored,
      );
      setNodes(initialNodes);
      setEdges(initialEdges);
    }
  }, [
    playbook,
    pivotsLoading,
    playbooksLoading,
    setNodes,
    setEdges,
    pivotStored,
    playbooksStored,
  ]);

  return (
    <div
      id="PlaybookFlows"
      className="pt-4"
      style={{ width: "100%", height: "500px", overflowX: "scroll" }}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        defaultEdgeOptions={defaultEdgeOptions}
        defaultViewport={{ x: 0, y: 0, zoom: 1 }}
        nodeTypes={nodeTypes}
        deleteKeyCode={null}
        preventScrolling
        zoomOnDoubleClick={false}
      >
        <Controls />
      </ReactFlow>
    </div>
  );
}

PlaybookFlows.propTypes = {
  playbook: PropTypes.object.isRequired,
};
