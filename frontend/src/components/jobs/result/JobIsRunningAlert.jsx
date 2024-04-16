/* eslint-disable id-length */
import React from "react";
import PropTypes from "prop-types";
import ReactFlow, { MarkerType } from "reactflow";
import "reactflow/dist/style.css";
import { IconButton } from "@certego/certego-ui";

import CustomJobPipelineNode from "./CustomJobPipelineNode";
import { JobStatuses, JobFinalStatuses } from "../../../constants/jobConst";
import { areYouSureConfirmDialog } from "../../common/areYouSureConfirmDialog";

import {
  reportedPluginNumber,
  reportedVisualizerNumber,
} from "./utils/reportedPlugins";
import { killJob } from "./jobApi";
import { killJobIcon } from "../../common/icon/icons";

// Important! This must be defined outside of the component
const nodeTypes = {
  jobPipelineNode: CustomJobPipelineNode,
};

const defaultEdgeOptions = {
  style: { strokeWidth: 3 },
  type: "step",
  markerEnd: {
    type: MarkerType.ArrowClosed,
  },
};

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
  const analyzersCompleted = Object.values(JobStatuses)
    .slice(3)
    .includes(job.status);
  const connectorsCompleted = Object.values(JobStatuses)
    .slice(5)
    .includes(job.status);
  const pivotsCompleted = Object.values(JobStatuses)
    .slice(7)
    .includes(job.status);
  const visualizersCompleted = Object.values(JobStatuses)
    .slice(9)
    .includes(job.status);

  const nodes = [
    {
      id: `isRunningJob-analyzers`,
      position: { x: 0, y: 0 },
      data: {
        id: "step-1",
        label: "ANALYZERS",
        running: job.status === JobStatuses.ANALYZERS_RUNNING,
        completed:
          analizersReported === job.analyzers_to_execute.length &&
          analyzersCompleted,
        report: `${analizersReported}/${job.analyzers_to_execute.length}`,
      },
      type: "jobPipelineNode",
      draggable: false,
    },
    {
      id: `isRunningJob-connectors`,
      position: { x: 450, y: 0 },
      data: {
        id: "step-2",
        label: "CONNECTORS",
        running: job.status === JobStatuses.CONNECTORS_RUNNING,
        completed:
          connectorsReported === job.connectors_to_execute.length &&
          connectorsCompleted,
        report: `${connectorsReported}/${job.connectors_to_execute.length}`,
      },
      type: "jobPipelineNode",
      draggable: false,
    },
    {
      id: `isRunningJob-pivots`,
      position: { x: 900, y: 0 },
      data: {
        id: "step-3",
        label: "PIVOTS",
        running: job.status === JobStatuses.PIVOTS_RUNNING,
        completed:
          pivotsReported === job.pivots_to_execute.length && pivotsCompleted,
        report: `${pivotsReported}/${job.pivots_to_execute.length}`,
      },
      type: "jobPipelineNode",
      draggable: false,
    },
    {
      id: `isRunningJob-visualizers`,
      position: { x: 1350, y: 0 },
      data: {
        id: "step-4",
        label: "VISUALIZERS",
        running: job.status === JobStatuses.VISUALIZERS_RUNNING,
        completed:
          visualizersReported === job.visualizers_to_execute.length &&
          visualizersCompleted,
        report: `${visualizersReported}/${job.visualizers_to_execute.length}`,
      },
      type: "jobPipelineNode",
      draggable: false,
    },
  ];

  const edges = [
    {
      id: `edge-analyzers-connectors`,
      source: `isRunningJob-analyzers`,
      target: `isRunningJob-connectors`,
    },
    {
      id: `edge-connectors-pivots`,
      source: `isRunningJob-connectors`,
      target: `isRunningJob-pivots`,
    },
    {
      id: `edge-pivots-visualizers`,
      source: `isRunningJob-pivots`,
      target: `isRunningJob-visualizers`,
    },
  ];

  const onKillJobBtnClick = async () => {
    const sure = await areYouSureConfirmDialog(`Kill Job #${job.id}`);
    if (!sure) return null;
    await killJob(job.id);
    return null;
  };

  return (
    <>
      <div
        id="JobPipelineFlow"
        className="bg-body"
        style={{ width: 2000, height: 90 }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          defaultEdgeOptions={defaultEdgeOptions}
          defaultViewport={{ x: 0, y: 0, zoom: 1.2 }}
          nodeTypes={nodeTypes}
          deleteKeyCode={null}
          preventScrolling={false}
          zoomOnDoubleClick={false}
          panOnDrag={false}
          proOptions={{ hideAttribution: true }}
          fitView
        />
      </div>
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
