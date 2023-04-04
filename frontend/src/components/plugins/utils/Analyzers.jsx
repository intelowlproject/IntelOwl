import React from "react";

import { analyzersTableColumns } from "./data";
import PluginWrapper from "./PluginWrapper";
import { pluginType } from "../../../constants/constants";

export default function Analyzers() {
  console.debug("Analyzers rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.analyzersLoading,
      state.analyzersError,
      state.analyzers,
      state.retrieveAnalyzersConfiguration,
    ],
    []
  );

  return (
    <PluginWrapper
      heading="Analyzers"
      description="Analyzers are the most important plugins in IntelOwl. They allow to perform data extraction on the observables and/or files that you would like to analyze."
      stateSelector={stateSelector}
      columns={analyzersTableColumns}
      type={pluginType.ANALYZER}
    />
  );
}
