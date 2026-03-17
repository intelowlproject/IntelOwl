import React from "react";

import { pivotTableColumns } from "./pluginTableColumns";
import PluginWrapper from "./PluginWrapper";
import { PluginsTypes } from "../../../constants/pluginConst";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";

export default function Pivots() {
  console.debug("Pivots rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.pivotsLoading,
      state.pivotsError,
      state.pivots,
      state.retrievePivotsConfiguration,
    ],
    [],
  );

  const [pivotsLoading, , pivots, retrievePivotsConfiguration] =
    usePluginConfigurationStore(stateSelector);

  React.useEffect(() => {
    if (pivots.length === 0 && !pivotsLoading) {
      retrievePivotsConfiguration();
    }
  }, []);

  return (
    <PluginWrapper
      heading="Pivots"
      description="Pivots are designed to create a job from another job."
      stateSelector={stateSelector}
      columns={pivotTableColumns}
      type={PluginsTypes.PIVOT}
    />
  );
}
