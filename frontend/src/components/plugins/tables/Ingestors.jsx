import React from "react";

import { ingestorTableColumns } from "./pluginTableColumns";
import PluginWrapper from "./PluginWrapper";
import { PluginsTypes } from "../../../constants/pluginConst";

export default function Ingestors() {
  console.debug("Ingestors rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.ingestorsLoading,
      state.ingestorsError,
      state.ingestors,
      state.retrieveIngestorsConfiguration,
    ],
    [],
  );

  return (
    <PluginWrapper
      heading="Ingestors"
      description="Ingestors are designed to create jobs from an external source."
      stateSelector={stateSelector}
      columns={ingestorTableColumns}
      type={PluginsTypes.INGESTOR}
    />
  );
}
