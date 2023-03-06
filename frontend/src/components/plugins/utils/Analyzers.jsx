import React from "react";

import { analyzersTableColumns } from "./data";
import PluginWrapper from "./PluginWrapper";
import {ANALYZER} from "../../../constants/constants";

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
      stateSelector={stateSelector}
      columns={analyzersTableColumns}
      type={ANALYZER}
    />
  );
}
