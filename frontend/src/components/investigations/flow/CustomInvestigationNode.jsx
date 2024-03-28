import React from "react";
import PropTypes from "prop-types";
import { NodeToolbar, Handle, Position } from "reactflow";
import "reactflow/dist/style.css";
import { Button, UncontrolledTooltip } from "reactstrap";
import { FaSearchPlus } from "react-icons/fa";
import { AddExistingJobPopover } from "./investigationActions";

function CustomInvestigationNode({ data }) {
  return (
    <>
      <NodeToolbar
        position="right"
        style={{
          background: "#000f12",
        }}
        id={`toolbar-investigation-${data.id}`}
      >
        <div className="p-1 my-2 d-flex justify-content-start">
          <div>
            <Button
              className="mx-1 p-2"
              size="sm"
              href={`/scan?investigation=${data.id}`}
              target="_blank"
              rel="noreferrer"
              id="createJobBtn"
            >
              <FaSearchPlus /> Create Job
            </Button>
            <UncontrolledTooltip placement="top" target="createJobBtn">
              Scan a new observable or a file to add to this investigation
            </UncontrolledTooltip>
          </div>
          <AddExistingJobPopover data={data} />
        </div>
      </NodeToolbar>
      <div
        className="react-flow__node-input"
        id={`investigation-${data.id}`}
        style={{
          background: "#0b2b38",
          color: "#D6D5E6",
          border: "1px solid #2f515e",
          minWidth: "250px",
        }}
      >
        <strong>{data?.label}</strong>
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        id={`investigationHandle-${data.id}`}
        isConnectable
      />
    </>
  );
}

CustomInvestigationNode.propTypes = {
  data: PropTypes.object.isRequired,
};

export default React.memo(CustomInvestigationNode);
