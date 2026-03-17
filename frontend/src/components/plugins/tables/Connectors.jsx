import React from "react";

import { connectorTableColumns } from "./pluginTableColumns";
import PluginWrapper from "./PluginWrapper";
import { PluginsTypes } from "../../../constants/pluginConst";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";

export default function Connectors() {
  console.debug("Connectors rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.connectorsLoading,
      state.connectorsError,
      state.connectors,
      state.retrieveConnectorsConfiguration,
    ],
    [],
  );

  const [connectorsLoading, , connectors, retrieveConnectorsConfiguration] =
    usePluginConfigurationStore(stateSelector);

  React.useEffect(() => {
    if (connectors.length === 0 && !connectorsLoading) {
      retrieveConnectorsConfiguration();
    }
  }, []);

  return (
    <PluginWrapper
      heading="Connectors"
      description="Connectors are designed to run after every successful analysis which makes them suitable for automated threat-sharing. They support integration with other SIEM/SOAR projects, specifically aimed at Threat Sharing Platforms."
      stateSelector={stateSelector}
      columns={connectorTableColumns}
      type={PluginsTypes.CONNECTOR}
    />
  );
}
