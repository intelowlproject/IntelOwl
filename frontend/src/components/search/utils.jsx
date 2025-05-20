import React from "react";
import PropTypes from "prop-types";

import { JsonEditor } from "../common/JsonEditor";
import { useJsonEditorStore } from "../../stores/useJsonEditorStore";

export function SearchJSONReport({ row }) {
  // store
  const [textToHighlight] = useJsonEditorStore((state) => [
    state.textToHighlight,
  ]);
  return (
    <div
      id={`jobreport-jsoninput-${row.id}`}
      style={{ maxHeight: "50vh", overflow: "scroll" }}
    >
      <JsonEditor
        id="plugin_report_json"
        initialJsonData={row.original?.report}
        width="100%"
        readOnly
        textToHighlight={textToHighlight}
      />
    </div>
  );
}

SearchJSONReport.propTypes = {
  row: PropTypes.object.isRequired,
};
