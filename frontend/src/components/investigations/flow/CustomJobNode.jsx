import React from "react";
import PropTypes from "prop-types";
import { NodeToolbar, Handle, Position } from "reactflow";
import "reactflow/dist/style.css";
import { Button } from "reactstrap";
import { AiOutlineLink } from "react-icons/ai";
import { LuGitBranchPlus } from "react-icons/lu";

import { RemoveJob } from "./investigationActions";

function CustomJobNode({ data }) {
  return (
    <>
      {/* Number of children */}
      <NodeToolbar position="top" align="end" isVisible offset={3}>
        <div className="pe-2 text-secondary">{data.children.length} items</div>
      </NodeToolbar>
      {/* Actions */}
      <NodeToolbar
        position="right"
        style={{
          background: "#000f12",
        }}
        id={`toolbar-job-${data.id}`}
      >
        <div className="p-1 my-2 d-flex justify-content-start">
          <Button
            className="ms-2 me-1 p-2"
            size="sm"
            href={`/jobs/${data.id}/visualizer`}
            target="_blank"
            rel="noreferrer"
          >
            <AiOutlineLink /> Link
          </Button>
          <Button
            className="mx-1 p-2"
            size="sm"
            href={`/scan?parent=${data.id}&observable=${data.name}`}
            target="_blank"
            rel="noreferrer"
          >
            <LuGitBranchPlus /> Pivot
          </Button>
          {data.isFirstLevel && <RemoveJob data={data} />}
        </div>
        <div
          className="p-2 px-3 my-2 mx-2 d-flex flex-column bg-body"
          id={`job${data.id}-info`}
        >
          <div className="d-flex justify-content-between">
            <span className="me-2">Job:</span>
            <span className="text-accent">#{data.id}</span>
          </div>
          <div className="d-flex justify-content-between">
            <span className="me-2">Name:</span>
            <span className="text-accent">{data?.name}</span>
          </div>
          <div className="d-flex justify-content-between">
            <span className="me-2">Playbook:</span>
            <span className="text-accent">{data?.playbook}</span>
          </div>
        </div>
      </NodeToolbar>
      <div
        className="react-flow__node-default d-block text-truncate"
        id={`job-${data.id}`}
        style={{
          background: "#2f515e",
          color: "#D6D5E6",
          border: "1px solid #5593ab",
          minWidth: "250px",
        }}
      >
        {data?.name}
      </div>
      <Handle
        type="source"
        position={Position.Right}
        id={`jobHandleSource-${data.id}`}
        isConnectable
      />
      <Handle
        type="target"
        position={Position.Left}
        id={`jobHandleTarget-${data.id}`}
        isConnectable
      />
    </>
  );
}

CustomJobNode.propTypes = {
  data: PropTypes.object.isRequired,
};

export default React.memo(CustomJobNode);
