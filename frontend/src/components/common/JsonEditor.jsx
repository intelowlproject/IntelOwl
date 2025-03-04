import React from "react";
import PropTypes from "prop-types";
import AceEditor from "react-ace";
import { Range } from "ace-builds";
import "ace-builds/src-noconflict/ext-language_tools";

const ace = require("ace-builds/src-noconflict/ace");

// ace config
ace.config.set(
  "basePath",
  "https://cdn.jsdelivr.net/npm/ace-builds@1.4.3/src-noconflict/",
);
ace.config.setModuleUrl(
  "ace/mode/json_worker",
  "https://cdn.jsdelivr.net/npm/ace-builds@1.4.3/src-noconflict/worker-json.js",
);
ace.config.setModuleLoader(
  "ace/mode/json",
  () => import("ace-builds/src-noconflict/mode-json"),
);
ace.config.setModuleLoader(
  "ace/theme/solarized_dark",
  () => import("ace-builds/src-noconflict/theme-solarized_dark"),
);

export function JsonEditor({
  id,
  initialJsonData,
  onChange,
  height,
  width,
  readOnly,
  levelToOpen,
  textToHighlight,
}) {
  console.debug("JsonEditor rendered");

  const [currentJsonData, setCurrentJsonData] = React.useState(initialJsonData);

  const getMarkers = (editor, indexes) => {
    const markers = [];
    if (indexes.length) {
      indexes.forEach((index) => {
        const start = editor.session.doc.indexToPosition(index);
        markers.push({
          startRow: start.row,
          startCol: start.col,
          endRow: start.row,
          endCol: 0,
        });
      });
      return markers;
    }
    return null;
  };

  return (
    <AceEditor
      mode="json"
      theme="solarized_dark"
      height={height}
      width={width}
      readOnly={readOnly}
      onChange={(newJsonData) => {
        if (!readOnly) {
          try {
            setCurrentJsonData(JSON.parse(newJsonData));
            onChange(JSON.parse(newJsonData));
          } catch (error) {
            // errors are shown automatically in annotations
          }
        }
      }}
      name={`jsonAceEditor__${id}`}
      editorProps={{ $blockScrolling: true }}
      placeholder="no data"
      fontSize={14}
      lineHeight={19}
      showPrintMargin={false}
      showGutter
      highlightActiveLine={!readOnly}
      value={JSON.stringify(currentJsonData, null, 2)}
      setOptions={{
        enableMobileMenu: true,
        showLineNumbers: true,
        tabSize: 2,
        dragEnabled: false,
      }}
      onLoad={(editor) => {
        const editorSession = editor.getSession();
        if (levelToOpen !== 0) return editorSession.foldToLevel(levelToOpen);
        if (textToHighlight !== "") {
          const matches = [
            ...JSON.stringify(currentJsonData, null, 2).matchAll(
              new RegExp(textToHighlight, "gi"),
            ),
          ];
          const indexes = matches.map((match) => match.index);
          getMarkers(editor, indexes)?.forEach((marker) =>
            editor.session.addMarker(
              new Range(
                marker.startRow,
                marker.startCol,
                marker.endRow,
                marker.endCol,
              ),
              "custom-ace-marker",
              "fullLine",
            ),
          );
        }
        return null;
      }}
      annotations={[]}
    />
  );
}

JsonEditor.propTypes = {
  initialJsonData: PropTypes.object.isRequired,
  id: PropTypes.string.isRequired,
  onChange: PropTypes.func,
  height: PropTypes.string,
  width: PropTypes.string,
  readOnly: PropTypes.bool,
  levelToOpen: PropTypes.number,
  textToHighlight: PropTypes.string,
};

JsonEditor.defaultProps = {
  onChange: () => null,
  height: "500px",
  width: "500px",
  readOnly: false,
  levelToOpen: 0,
  textToHighlight: "",
};
