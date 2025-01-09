import React from "react";
import PropTypes from "prop-types";
import { Handle, Position, NodeToolbar } from "reactflow";
import "reactflow/dist/style.css";
import { Badge } from "reactstrap";

function CustomPlaybookNode({ data }) {
  return (
    <>
      {/* Badge */}
      <NodeToolbar position="top" align="start" isVisible offset={3}>
        <Badge color="#5593ab" style={{ backgroundColor: "#5593ab" }}>
          Playbook
        </Badge>
      </NodeToolbar>
      {/* Info */}
      <NodeToolbar
        position="right"
        style={{
          background: "#000f12",
          border: "1px solid #6c757d",
          borderRadius: "10px",
        }}
        id={`toolbar-pivot-${data.id}`}
        className="p-3 px-4 my-2 mx-2 d-flex flex-column bg-body"
      >
        <small
          className="d-flex justify-content-between"
          style={{ maxWidth: "25vh" }}
        >
          <span>{data?.description}</span>
        </small>
      </NodeToolbar>
      <div
        className="react-flow__node-input"
        id={`playbook-${data.id}`}
        style={{
          background: "#2f515e",
          color: "#fff",
          border: "1px solid #5593ab",
          minWidth: "250px",
        }}
      >
        <strong>{data?.label}</strong>
      </div>
      <Handle
        type="source"
        position={Position.Right}
        id={`playbookHandleSource-${data.id}`}
        isConnectable
      />
      <Handle
        type="target"
        position={Position.Left}
        id={`playbookHandleTarget-${data.id}`}
        isConnectable
      />
    </>
  );
}

CustomPlaybookNode.propTypes = {
  data: PropTypes.object.isRequired,
};

export default React.memo(CustomPlaybookNode);
