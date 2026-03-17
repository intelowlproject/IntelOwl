import React from "react";

import { analyzersTableColumns } from "./pluginTableColumns";
import PluginWrapper from "./PluginWrapper";
import { PluginsTypes } from "../../../constants/pluginConst";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";

export default function Analyzers() {
  console.debug("Analyzers rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.analyzersLoading,
      state.analyzersError,
      state.analyzers,
      state.retrieveAnalyzersConfiguration,
    ],
    [],
  );

  const [analyzersLoading, , analyzers, retrieveAnalyzersConfiguration] =
    usePluginConfigurationStore(stateSelector);

  React.useEffect(() => {
    if (analyzers.length === 0 && !analyzersLoading) {
      retrieveAnalyzersConfiguration();
    }
  }, []);

  return (
    <PluginWrapper
      heading="Analyzers"
      description="Analyzers are the most important plugins in IntelOwl. They allow to perform data extraction on the observables and/or files that you would like to analyze."
      stateSelector={stateSelector}
      columns={analyzersTableColumns}
      type={PluginsTypes.ANALYZER}
    />
  );
}
