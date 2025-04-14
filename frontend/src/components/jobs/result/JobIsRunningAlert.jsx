/* eslint-disable id-length */
import React from "react";
import PropTypes from "prop-types";
import { ReactFlowProvider } from "reactflow";
import "reactflow/dist/style.css";
import { IconButton } from "@certego/certego-ui";

import { JobFinalStatuses } from "../../../constants/jobConst";
import { areYouSureConfirmDialog } from "../../common/areYouSureConfirmDialog";

import { killJob } from "./jobApi";
import { killJobIcon } from "../../common/icon/actionIcons";
import { JobIsRunningFlow } from "./flow/JobIsRunningFlow";

export function JobIsRunningAlert({ job }) {
  const onKillJobBtnClick = async () => {
    const sure = await areYouSureConfirmDialog(`Kill Job #${job.id}`);
    if (!sure) return null;
    await killJob(job.id);
    return null;
  };

  return (
    <>
      <ReactFlowProvider>
        <JobIsRunningFlow job={job} />
      </ReactFlowProvider>
      <div className="d-flex-center">
        {job.permissions?.kill &&
          !Object.values(JobFinalStatuses).includes(job.status) && (
            <IconButton
              id="killjob-iconbutton"
              Icon={killJobIcon}
              size="xs"
              title="Stop Job Process"
              color="danger"
              titlePlacement="top"
              onClick={onKillJobBtnClick}
              className="mt-4"
            />
          )}
      </div>
    </>
  );
}

JobIsRunningAlert.propTypes = {
  job: PropTypes.object.isRequired,
};
