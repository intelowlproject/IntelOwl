import React from "react";
import PropTypes from "prop-types";
import { Handle, Position } from "reactflow";
import "reactflow/dist/style.css";
import { StatusIcon } from "../../../common/icon/StatusIcon";

function CustomJobPipelineNode({ data }) {
  let statusIcon = "pending";
  if (data.completed) statusIcon = "success";
  else if (data.running) statusIcon = "running";

  return (
    <>
      <div
        className="react-flow__node-default d-flex align-items-center"
        id={`jobPipeline-${data.id}`}
        style={{
          background: "#5593ab",
          color: "#D6D5E6",
          border: "1px solid #2f515e",
          minWidth: "350px",
          opacity: !(data.running || data.completed) && "60%",
        }}
      >
        <StatusIcon
          size="15%"
          status={statusIcon}
          className={`${!data.completed && "text-dark"} m-2`}
        />
        <div className="d-flex-start-start flex-column ms-2">
          <h6 className="mt-2 mb-1 fw-bold text-darker">
            {data?.label} {data.running && "RUNNING"}
            {data.completed && "COMPLETED"}{" "}
          </h6>
          <strong className="fs-6">Reported {data.report}</strong>
        </div>
      </div>
      <Handle
        type="source"
        position={Position.Right}
        id={`jobPipelineHandle-${data.id}`}
        isConnectable
        hidden={data?.id === "step-4"}
        style={{ opacity: "0" }}
      />
      <Handle
        type="target"
        position={Position.Left}
        id={`jobPipelineHandle-${data.id}`}
        isConnectable
        hidden={data?.id === "step-1"}
        style={{ opacity: "0" }}
      />
    </>
  );
}

CustomJobPipelineNode.propTypes = {
  data: PropTypes.object.isRequired,
};

export default React.memo(CustomJobPipelineNode);
