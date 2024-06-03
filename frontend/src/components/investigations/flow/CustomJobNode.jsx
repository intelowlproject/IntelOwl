import React from "react";
import PropTypes from "prop-types";
import { NodeToolbar, Handle, Position } from "reactflow";
import "reactflow/dist/style.css";
import { Button, UncontrolledTooltip } from "reactstrap";
import { AiOutlineLink } from "react-icons/ai";
import { LuGitBranchPlus } from "react-icons/lu";
import { MdContentCopy } from "react-icons/md";

import { CopyToClipboardButton, DateHoverable } from "@certego/certego-ui";

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
          <CopyToClipboardButton
            id="investigation-copybtn"
            text={data.name}
            className="mx-1 p-2 btn btn-secondary btn-sm"
            showOnHover
          >
            <MdContentCopy /> Copy
          </CopyToClipboardButton>
          <Button
            id="investigation-linkbtn"
            className="mx-1 p-2"
            size="sm"
            href={`/jobs/${data.id}/visualizer`}
            target="_blank"
            rel="noreferrer"
          >
            <AiOutlineLink /> Link
          </Button>
          <UncontrolledTooltip
            target="investigation-linkbtn"
            placement="top"
            fade={false}
          >
            Go to job #{data.id} result page
          </UncontrolledTooltip>
          <Button
            id="investigation-pivotbtn"
            className="mx-1 p-2"
            size="sm"
            href={`/scan?parent=${data.id}&observable=${data.name}`}
            target="_blank"
            rel="noreferrer"
          >
            <LuGitBranchPlus /> Pivot
          </Button>
          <UncontrolledTooltip
            target="investigation-pivotbtn"
            placement="top"
            fade={false}
          >
            Analyze the same observable again
          </UncontrolledTooltip>
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
            <span className="text-accent">
              {data?.playbook || "Custom analysis"}
            </span>
          </div>
          <div className="d-flex justify-content-between">
            <span className="me-2">Created:</span>
            <span className="text-accent">
              <DateHoverable
                className="text-accent"
                ago
                value={data?.created}
                format="hh:mm:ss a MMM do, yyyy"
              />
            </span>
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
