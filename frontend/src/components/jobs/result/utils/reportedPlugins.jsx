import React from "react";
import PropTypes from "prop-types";
import { UncontrolledTooltip } from "reactstrap";
import { PluginFinalStatuses } from "../../../../constants/pluginConst";

export function reportedVisualizerNumber(
  visualizersReportedList,
  visualizersToExecute,
) {
  /**
   * Return the number of visualizer in the final statuses
   */
  let visualizersNumber = 0;
  visualizersToExecute.forEach((visualizer) => {
    // count reports that have 'config' === 'visualizer' (pages from the same visualizer) and are in a final statuses
    let visualizersInFinalStatus = 0;
    let visualizerPages = 0;
    visualizersReportedList.forEach((report) => {
      if (report.config === visualizer) {
        visualizerPages += 1;
        if (Object.values(PluginFinalStatuses).includes(report.status))
          visualizersInFinalStatus += 1;
      }
    });
    // visualizer is completed if all pages are in a final statuses
    if (visualizersInFinalStatus === visualizerPages) visualizersNumber += 1;
  });
  return visualizersNumber;
}

export function reportedPluginNumber(pluginList) {
  /**
   * Return the number of plugin in the final statuses
   */
  return pluginList
    .map((report) => report.status)
    .filter((status) => Object.values(PluginFinalStatuses).includes(status))
    .length;
}

export function ReportedPluginTooltip({ id, pluginName }) {
  return (
    <UncontrolledTooltip placement="top" target={id}>
      {pluginName} reported / {pluginName} executed
    </UncontrolledTooltip>
  );
}

ReportedPluginTooltip.propTypes = {
  id: PropTypes.string.isRequired,
  pluginName: PropTypes.string.isRequired,
};
