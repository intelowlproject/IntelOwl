import React from "react";

import { playbookTableColumns } from "./data";
import PluginWrapper from "./PluginWrapper";

export default function Playbooks() {
  console.debug("Playbooks rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.loading,
      state.error,
      state.playbooks,
      state.retrievePlaybooksConfiguration,
    ],
    [],
  );

  return (
    <PluginWrapper
      heading="Playbooks"
      stateSelector={stateSelector}
      columns={playbookTableColumns}
    />
  );
}
