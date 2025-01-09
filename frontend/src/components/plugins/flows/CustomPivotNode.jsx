import React from "react";
import PropTypes from "prop-types";
import { Handle, Position, NodeToolbar } from "reactflow";
import "reactflow/dist/style.css";
import { Badge } from "reactstrap";

function CustomPivotNode({ data }) {
  return (
    <>
      <NodeToolbar position="top" align="start" isVisible offset={3}>
        <Badge color="#b5ba66" style={{ backgroundColor: "#b5ba66" }}>
          Pivot
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
        <small className="d-flex justify-content-between">
          <span className="me-4">Analyzers:</span>
          <span style={{ color: "#b5ba66" }}>{data?.analyzers || "-"}</span>
        </small>
        <small className="d-flex justify-content-between">
          <span className="me-4">Connectors:</span>
          <span style={{ color: "#b5ba66" }}>{data?.connectors || "-"}</span>
        </small>
        <small className="d-flex justify-content-between">
          <span className="me-4">Type:</span>
          <span style={{ color: "#b5ba66" }}>{data?.type}</span>
        </small>
        <small className="d-flex justify-content-between">
          <span className="me-4"> Field to analyze:</span>
          <span style={{ color: "#b5ba66" }}>
            {data?.fieldToCompare || "-"}
          </span>
        </small>
      </NodeToolbar>
      <div
        className="react-flow__node-input"
        id={`pivot-${data.id}`}
        style={{
          background: "#2f515e",
          color: "#fff",
          border: "1px solid #b5ba66",
          minWidth: "250px",
        }}
      >
        <strong>{data?.label}</strong>
      </div>
      <Handle
        type="source"
        position={Position.Right}
        id={`pivotHandleSource-${data.id}`}
        isConnectable
      />
      <Handle
        type="target"
        position={Position.Left}
        id={`pivotHandleTarget-${data.id}`}
        isConnectable
      />
    </>
  );
}

CustomPivotNode.propTypes = {
  data: PropTypes.object.isRequired,
};

export default React.memo(CustomPivotNode);
