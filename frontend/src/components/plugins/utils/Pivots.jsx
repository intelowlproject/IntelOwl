import React from "react";

import { pivotTableColumns } from "./data";
import PluginWrapper from "./PluginWrapper";
import { pluginType } from "../../../constants/constants";

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

  return (
    <PluginWrapper
      heading="Pivots"
      description="Pivots are designed to create a job from another job"
      stateSelector={stateSelector}
      columns={pivotTableColumns}
      type={pluginType.PIVOT}
    />
  );
}
