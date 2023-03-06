import React from "react";

import { connectorTableColumns } from "./data";
import PluginWrapper from "./PluginWrapper";
import { pluginType } from "../../../constants/constants";

export default function Connectors() {
  console.debug("Connectors rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.connectorsLoading,
      state.connectorsError,
      state.connectors,
      state.retrieveConnectorsConfiguration,
    ],
    []
  );

  return (
    <PluginWrapper
      heading="Connectors"
      stateSelector={stateSelector}
      columns={connectorTableColumns}
      type={pluginType.CONNECTOR}
    />
  );
}
