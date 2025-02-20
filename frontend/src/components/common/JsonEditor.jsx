import React from "react";
import PropTypes from "prop-types";
import AceEditor from "react-ace";

import "ace-builds/src-noconflict/mode-json";
import "ace-builds/src-noconflict/theme-solarized_dark";
import "ace-builds/src-noconflict/ext-language_tools";

const ace = require("ace-builds/src-noconflict/ace");

ace.config.set(
  "basePath",
  "https://cdn.jsdelivr.net/npm/ace-builds@1.4.3/src-noconflict/",
);
ace.config.setModuleUrl(
  "ace/mode/json_worker",
  "https://cdn.jsdelivr.net/npm/ace-builds@1.4.3/src-noconflict/worker-json.js",
);

export function JsonEditor({
  id,
  initialJsonData,
  onChange,
  height,
  width,
  readOnly,
  levelToOpen,
}) {
  const [currentJsonData, setCurrentJasonData] =
    React.useState(initialJsonData);

  return (
    <AceEditor
      mode="json"
      theme="solarized_dark"
      height={height}
      width={width}
      readOnly={readOnly}
      onChange={(newJsonData) => {
        try {
          setCurrentJasonData(JSON.parse(newJsonData));
          onChange(JSON.parse(newJsonData));
        } catch (error) {
          // errors are shown automatically in annotations
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
        return null;
      }}
      annotations={[]}
    />
  );
}

JsonEditor.propTypes = {
  initialJsonData: PropTypes.object.isRequired,
  onChange: PropTypes.func.isRequired,
  id: PropTypes.string.isRequired,
  height: PropTypes.string,
  width: PropTypes.string,
  readOnly: PropTypes.bool,
  levelToOpen: PropTypes.number,
};

JsonEditor.defaultProps = {
  height: "500px",
  width: "500px",
  readOnly: false,
  levelToOpen: 0,
};
