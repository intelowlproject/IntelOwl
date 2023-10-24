import React from "react";
import PropTypes from "prop-types";
import { Fade } from "reactstrap";
import { MdPauseCircleOutline } from "react-icons/md";

import { IconAlert, IconButton } from "@certego/certego-ui";

import { killJob } from "./jobApi";
import { jobStatuses } from "../../../constants/constants";

import {
  reportedPluginNumber,
  reportedVisualizerNumber,
} from "./utils/reportedPlugins";

export function JobIsRunningAlert({ job }) {
  // number of analyzers/connectors/visualizers reported (status: killed/succes/failed)
  const analizersReported = reportedPluginNumber(job.analyzer_reports);
  const connectorsReported = reportedPluginNumber(job.connector_reports);
  const pivotsReported = reportedPluginNumber(job.pivot_reports);
  const visualizersReported = reportedVisualizerNumber(
    job.visualizer_reports,
    job.visualizers_to_execute,
  );

  /* Check if analyzers/connectors/visualizers are completed
      The analyzers are completed from the "analyzers_completed" status (index=3) to the last status 
      The connectors are completed from the "connectors_completed" status (index=5) to the last status 
      The visualizers are completed from the "visualizers_completed" status (index=7) to the last status 
    */
  const analyzersCompleted = Object.values(jobStatuses)
    .slice(3)
    .includes(job.status);
  const connectorsCompleted = Object.values(jobStatuses)
    .slice(5)
    .includes(job.status);
  const pivotsCompleted = Object.values(jobStatuses)
    .slice(7)
    .includes(job.status);
  const visualizersCompleted = Object.values(jobStatuses)
    .slice(9)
    .includes(job.status);

  const alertElements = [
    {
      step: 1,
      type: "ANALYZERS",
      completed:
        analizersReported === job.analyzers_to_execute.length &&
        analyzersCompleted,
      report: `${analizersReported}/${job.analyzers_to_execute.length}`,
    },
    {
      step: 2,
      type: "CONNECTORS",
      completed:
        connectorsReported === job.connectors_to_execute.length &&
        connectorsCompleted,
      report: `${connectorsReported}/${job.connectors_to_execute.length}`,
    },
    {
      step: 3,
      type: "PIVOTS",
      completed:
        pivotsReported === job.pivots_to_execute.length && pivotsCompleted,
      report: `${pivotsReported}/${job.pivots_to_execute.length}`,
    },
    {
      step: 4,
      type: "VISUALIZERS",
      completed:
        visualizersReported === job.visualizers_to_execute.length &&
        visualizersCompleted,
      report: `${visualizersReported}/${job.visualizers_to_execute.length}`,
    },
  ];

  return (
    <Fade className="d-flex-center mx-auto">
      <IconAlert
        id="jobisrunningalert-iconalert"
        color="info"
        className="text-info text-center"
      >
        <h6>
          This job is currently <strong className="text-accent">running</strong>
          .
        </h6>
        {alertElements.map((element) => (
          <div className="text-white">
            STEP {element.step}: {element.type} RUNNING -
            <strong
              className={`text-${element.completed ? "success" : "info"}`}
            >
              &nbsp;reported {element.report}
            </strong>
          </div>
        ))}
        {job.permissions?.kill && (
          <IconButton
            id="jobisrunningalert-iconbutton"
            Icon={MdPauseCircleOutline}
            size="xs"
            title="Stop Job Process"
            color="danger"
            titlePlacement="top"
            onClick={() => killJob(job.id)}
            className="mt-2"
          />
        )}
        <div className="text-gray">
          The page will auto-refresh once the analysis completes. You can either
          wait here or come back later and check.
        </div>
      </IconAlert>
    </Fade>
  );
}

JobIsRunningAlert.propTypes = {
  job: PropTypes.object.isRequired,
};
