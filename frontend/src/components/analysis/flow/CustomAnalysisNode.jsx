import React from "react";
import PropTypes from "prop-types";
import { NodeToolbar, Handle, Position } from "reactflow";
import "reactflow/dist/style.css";
import {
  Button,
  UncontrolledTooltip,
  UncontrolledPopover,
  Input,
} from "reactstrap";
import { FaSearchPlus } from "react-icons/fa";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { addJob } from "../result/analysisApi";

function CustomAnalysisNode({ data }) {
  // state
  const [jobToAdd, setJobToAdd] = React.useState(null);

  const addExistingJob = async () => {
    const success = await addJob(data.id, jobToAdd);
    if (success) {
      data.refetchTree();
    }
    setJobToAdd(null);
  };

  return (
    <>
      <NodeToolbar
        position="right"
        style={{
          background: "#000f12",
        }}
      >
        <div className="p-1 my-2 d-flex justify-content-start">
          <div>
            <Button
              className="mx-1 p-2"
              size="sm"
              href={`/scan?analysis=${data.id}`}
              target="_blank"
              rel="noreferrer"
              id="createJobBtn"
            >
              <FaSearchPlus /> Create Job
            </Button>
            <UncontrolledTooltip placement="top" target="createJobBtn">
              Scan a new observable or a file to add to this analysis
            </UncontrolledTooltip>
          </div>
          <div>
            <Button className="mx-1 p-2" size="sm" id="addExistingJobBtn">
              <BsFillPlusCircleFill /> Add existing job
            </Button>
            <UncontrolledPopover
              trigger="click"
              delay={{ show: 0, hide: 100 }}
              target="addExistingJobBtn"
              popperClassName="p-0"
              style={{ maxWidth: "70vh" }}
            >
              <div className="d-flex">
                <Input
                  id="add_existing_job-input"
                  name="textArea"
                  type="textarea"
                  onChange={(event) => setJobToAdd(event.target.value)}
                  placeholder="Enter a job id"
                  style={{ maxHeight: "40px", maxWidth: "60vh" }}
                  className="bg-dark"
                />
                <Button
                  className="mx-1 p-2"
                  size="sm"
                  id="addExistingJobBtn"
                  disabled={!jobToAdd}
                  onClick={() => addExistingJob()}
                >
                  Add
                </Button>
              </div>
            </UncontrolledPopover>
          </div>
        </div>
      </NodeToolbar>
      <div
        className="react-flow__node-input"
        id={`analysis-${data.id}`}
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
        id={`analysisHandle-${data.id}`}
        isConnectable
      />
    </>
  );
}

CustomAnalysisNode.propTypes = {
  data: PropTypes.object.isRequired,
};

export default React.memo(CustomAnalysisNode);
