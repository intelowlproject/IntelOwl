import React from "react";

import { visualizerTableColumns } from "./data";
import PluginWrapper from "./PluginWrapper";

export default function Visualizers() {
  console.debug("Visualizers rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.loading,
      state.error,
      state.visualizers,
      state.retrieveConnectorsConfiguration,
    ],
    []
  );

  return (
    <PluginWrapper
      heading="Visualizers"
      stateSelector={stateSelector}
      columns={visualizerTableColumns}
      type={3}
    />
  );
}
