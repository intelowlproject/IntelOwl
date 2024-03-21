import React from "react";
import PropTypes from "prop-types";
import {
  Button,
  Input,
  UncontrolledPopover,
  UncontrolledTooltip,
} from "reactstrap";
import { MdOutlineCancel } from "react-icons/md";
import { BsFillPlusCircleFill } from "react-icons/bs";

import { removeJob, addExistingJob } from "../result/investigationApi";

export function AddExistingJobPopover({ data }) {
  // state
  const [jobToAdd, setJobToAdd] = React.useState(null);

  const onClick = async () => {
    const success = await addExistingJob(jobToAdd, data.id);
    if (success) {
      data.refetchInvestigation();
      data.refetchTree();
    }
    setJobToAdd(null);
  };

  return (
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
        id="add_existing_job-popover"
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
            id="addExistingJob-Btn"
            disabled={!jobToAdd}
            onClick={() => onClick()}
          >
            Add
          </Button>
        </div>
      </UncontrolledPopover>
    </div>
  );
}

AddExistingJobPopover.propTypes = {
  data: PropTypes.object.isRequired,
};

export function RemoveJob({ data }) {
  const onClick = async () => {
    const success = await removeJob(data.investigation, data.id);
    if (success) {
      data.refetchInvestigation();
      data.refetchTree();
    }
  };

  return (
    <>
      <Button
        id="investigation-removejobbtn"
        className="mx-1 p-2"
        size="sm"
        onClick={() => onClick()}
      >
        <MdOutlineCancel color="red" /> Remove Branch
      </Button>
      <UncontrolledTooltip
        target="investigation-removejobbtn"
        placement="top"
        fade={false}
      >
        Remove job #{data.id} and all its children from the investigation
      </UncontrolledTooltip>
    </>
  );
}

RemoveJob.propTypes = {
  data: PropTypes.object.isRequired,
};
