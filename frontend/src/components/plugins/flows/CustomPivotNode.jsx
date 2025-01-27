import React from "react";
import PropTypes from "prop-types";
import { Handle, Position, NodeToolbar } from "reactflow";
import "reactflow/dist/style.css";
import { Badge } from "reactstrap";
import { IoMdWarning } from "react-icons/io";

function CustomPivotNode({ data }) {
  return (
    <>
      <NodeToolbar position="top" align="start" isVisible offset={3}>
        <Badge className="bg-advisory">Pivot</Badge>
        {data?.warning && (
          <IoMdWarning
            id="pivot-warning-icon"
            className="text-warning my-1 ms-1"
          />
        )}
      </NodeToolbar>
      {/* Info */}
      <NodeToolbar
        position="right"
        style={{
          border: "1px solid #6c757d",
          borderRadius: "10px",
        }}
        id={`toolbar-pivot-${data.id}`}
        className="p-3 px-4 my-2 mx-2 d-flex flex-column bg-body"
      >
        {data?.warning && (
          <div
            className="d-flex align-items-center px-1 mb-1"
            style={{ border: "1px solid #d98e16", borderRadius: "5px" }}
          >
            <IoMdWarning className="text-warning m-1" />
            <small className="me-1">
              This pivot will always fail as the playbook to execute is not
              configured or enabled
            </small>
          </div>
        )}
        <small className="d-flex justify-content-between">
          <span className="me-4">Analyzers:</span>
          <span className="text-advisory">{data?.analyzers || "-"}</span>
        </small>
        <small className="d-flex justify-content-between">
          <span className="me-4">Connectors:</span>
          <span className="text-advisory">{data?.connectors || "-"}</span>
        </small>
        <small className="d-flex justify-content-between">
          <span className="me-4">Type:</span>
          <span className="text-advisory">{data?.type}</span>
        </small>
        <small className="d-flex justify-content-between">
          <span className="me-4"> Field to analyze:</span>
          <span className="text-advisory">{data?.fieldToCompare || "-"}</span>
        </small>
      </NodeToolbar>
      <div
        className="react-flow__node-input border-advisory bg-tertiary text-white"
        id={`pivot-${data.id}`}
        style={{
          border: "1px solid",
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
