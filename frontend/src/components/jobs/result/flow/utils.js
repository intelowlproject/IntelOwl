/* eslint-disable id-length */
import {
  reportedPluginNumber,
  reportedVisualizerNumber,
} from "../utils/reportedPlugins";
import { JobStatuses } from "../../../../constants/jobConst";

export function getNodes(job) {
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

  const position = { x: 450, y: 0 };

  return [
    {
      id: `isRunningJob-analyzers`,
      position: { x: position.x * 0, y: position.y },
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
      position: { x: position.x, y: position.y },
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
      position: { x: position.x * 2, y: position.y },
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
      position: { x: position.x * 3, y: position.y },
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
}
