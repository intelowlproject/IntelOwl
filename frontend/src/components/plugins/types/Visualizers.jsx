import React from "react";

import { visualizerTableColumns } from "./pluginTableColumns";
import PluginWrapper from "./PluginWrapper";
import { PluginsTypes } from "../../../constants/pluginConst";

export default function Visualizers() {
  console.debug("Visualizers rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.visualizersLoading,
      state.visualizersError,
      state.visualizers,
      state.retrieveVisualizersConfiguration,
    ],
    [],
  );

  return (
    <PluginWrapper
      heading="Visualizers"
      description="Visualizers are designed to run after the analyzers and the connectors. The visualizer adds logic after the computations, allowing to show the final result in a different way than merely the list of reports."
      stateSelector={stateSelector}
      columns={visualizerTableColumns}
      type={PluginsTypes.VISUALIZER}
    />
  );
}
