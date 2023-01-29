import React from "react";

import { analyzersTableColumns } from "./data";
import PluginWrapper from "./PluginWrapper";

export default function Analyzers() {
  console.debug("Analyzers rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.loading,
      state.error,
      state.analyzers,
      state.retrieveAnalyzersConfiguration,
    ],
    [],
  );

  return (
    <PluginWrapper
      heading="Analyzers"
      stateSelector={stateSelector}
      columns={analyzersTableColumns}
      type={1}
    />
  );
}
