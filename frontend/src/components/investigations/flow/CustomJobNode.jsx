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
import {
  EvaluationBadge,
  ReliabilityBar,
  TagsBadge,
  CountryBadge,
  MimetypeBadge,
  IspBadge,
} from "../../common/engineBadges";

function CustomJobNode({ data }) {
  return (
    <>
      {/* Engine badges */}
      <NodeToolbar
        className="d-flex-center"
        position="top"
        align="start"
        isVisible
        offset={3}
      >
        <EvaluationBadge
          id={data.id}
          evaluation={data.engineFields.evaluation}
        />
        {data.engineFields?.mimetype && (
          <MimetypeBadge
            id={data.id}
            mimetype={data.engineFields.mimetype}
            className="ms-1"
          />
        )}
        {data.engineFields?.isp && (
          <IspBadge id={data.id} isp={data.engineFields.isp} className="ms-1" />
        )}
        {data.engineFields?.country && (
          <CountryBadge id={data.id} country={data.engineFields.country} />
        )}
      </NodeToolbar>
      <NodeToolbar
        className="d-flex-center"
        position="top"
        align="end"
        isVisible
        offset={3}
      >
        {data.engineFields.tags?.map((tag) => (
          <TagsBadge id={data.id} tag={tag} className="ms-1" />
        ))}
      </NodeToolbar>
      <NodeToolbar
        className="d-flex-center"
        position="bottom"
        align="start"
        isVisible
        offset={3}
      >
        <ReliabilityBar
          id={data.id}
          reliability={data.engineFields.reliability}
          evaluation={data.engineFields.evaluation}
        />
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
            href={`/scan?parent=${data.id}&${
              data.is_sample ? "isSample=true" : `observable=${data.name}`
            }`}
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
            Analyze the same observable again. CAUTION! Samples require to
            select again the file.
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
