import React from "react";
import PropTypes from "prop-types";
import { NodeToolbar, Handle, Position } from "reactflow";
import "reactflow/dist/style.css";
import { Button } from "reactstrap";

function AnalysisNode({ id, data }) {
  return (
    <>
      <NodeToolbar
        position="right"
        style={{
          background: "#000f12",
        }}
      >
        <div className="p-1 my-2 d-flex justify-content-start">
          <Button
            className="mx-1 p-2"
            size="sm"
            href={`/scan?analysis=${id}`}
            target="_blank"
            rel="noreferrer"
          >
            Create Job
          </Button>
          <Button className="mx-1 p-2" size="sm">
            Add Job
          </Button>
        </div>
      </NodeToolbar>
      <div
        className="react-flow__node-input"
        id={`analysis-${id}`}
        style={{
          background: "#0b2b38",
          color: "#D6D5E6",
          border: "1px solid #2f515e",
        }}
      >
        {data?.label}
      </div>
      <Handle type="source" position={Position.Bottom} id={id} isConnectable />
    </>
  );
}

AnalysisNode.propTypes = {
  id: PropTypes.string.isRequired,
  data: PropTypes.object.isRequired,
};

export default React.memo(AnalysisNode);
