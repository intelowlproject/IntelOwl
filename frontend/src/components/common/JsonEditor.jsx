import React from "react";
import PropTypes from "prop-types";
import JSONEditor from "jsoneditor";
import "jsoneditor/dist/jsoneditor.css";
import "./jsoneditortheme.css";

export function JsonEditor({ runtimeConfiguration }) {
  const jsonRef = React.useRef(null);

  const options = {
    mode: "tree",
    modes: ["tree"],
    search: false,
    name: "runtime_config",
    mainMenuBar: false,
    navigationBar: false,
    onChange: (event) => {
      console.debug(event);
    },
    onEditable: (node) => {
      // node is an object like:
      //   {
      //     field: 'FIELD',
      //     value: 'VALUE',
      //     path: ['PATH', 'TO', 'NODE']
      //   }
      if (node.path?.length === 3)
        return {
          field: false,
          value: true,
        };
      // defualt - not editable
      return false;
    },
    onEvent: (node, event) => {
      console.debug(node);
      console.debug(event);
    },
  };

  React.useEffect(() => {
    let jsonEditor = null;
    if (jsonRef.current) {
      jsonEditor = new JSONEditor(
        jsonRef.current,
        options,
        runtimeConfiguration,
      );
      jsonEditor.expandAll();
    }
    return () => jsonEditor?.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runtimeConfiguration]);

  return <div id="jsoneditor-react-container" ref={jsonRef} />;
}

JsonEditor.propTypes = {
  runtimeConfiguration: PropTypes.object.isRequired,
};
