import React from "react";
import { Modal, ModalHeader, ModalBody } from "reactstrap";
import PropTypes from "prop-types";

import { PluginsTypes } from "../../constants/pluginConst";
import { AnalyzerConfigForm } from "./forms/AnalyzerConfigForm";
import { PivotConfigForm } from "./forms/PivotConfigForm";
import { PlaybookConfigForm } from "./forms/PlaybookConfigForm";
import { PluginConfigContainer } from "./PluginConfigContainer";

export function PluginConfigModal({
  pluginConfig,
  pluginType,
  toggle,
  isOpen,
}) {
  console.debug("PluginConfigModal rendered!");

  const isEditing = Object.keys(pluginConfig).length > 0;
  const isBasicAnalyzer =
    pluginType === PluginsTypes.ANALYZER &&
    pluginConfig.python_module ===
      "basic_observable_analyzer.BasicObservableAnalyzer";

  let title = "Plugin config";
  // case A: DEFAULT plugin config
  let component = (
    <PluginConfigContainer
      pluginName={pluginConfig.name}
      pluginType={pluginType}
      toggle={toggle}
    />
  );
  if (isBasicAnalyzer || (pluginType === PluginsTypes.ANALYZER && !isEditing)) {
    title = "Edit analyzer config";
    // case B-C: create/edit basic analyzer
    component = (
      <AnalyzerConfigForm
        analyzerConfig={pluginConfig}
        toggle={toggle}
        isEditing={isEditing}
      />
    );
  } else if (pluginType === PluginsTypes.PIVOT) {
    title = "Edit pivot config";
    // case D-E: create/edit basic pivot
    component = (
      <PivotConfigForm
        pivotConfig={pluginConfig}
        toggle={toggle}
        isEditing={isEditing}
      />
    );
  } else if (pluginType === PluginsTypes.PLAYBOOK) {
    title = "Edit playbook config";
    // case F-G: create/edit playbook
    component = (
      <PlaybookConfigForm
        playbookConfig={pluginConfig}
        toggle={toggle}
        isEditing={isEditing}
      />
    );
  }

  return (
    <Modal
      id="plugin-config-modal"
      autoFocus
      centered
      zIndex="1050"
      size="lg"
      keyboard={false}
      backdrop="static"
      labelledBy="Plugin config modal"
      isOpen={isOpen}
      style={{ minWidth: "70%" }}
    >
      <ModalHeader className="mx-2" toggle={() => toggle(false)}>
        <small className="text-info">
          {isEditing ? title : `Create a new ${pluginType}`}
        </small>
      </ModalHeader>
      <ModalBody className="m-2">{component}</ModalBody>
    </Modal>
  );
}

PluginConfigModal.propTypes = {
  pluginConfig: PropTypes.object,
  pluginType: PropTypes.oneOf(Object.values(PluginsTypes)).isRequired,
  toggle: PropTypes.func.isRequired,
  isOpen: PropTypes.bool.isRequired,
};

PluginConfigModal.defaultProps = {
  pluginConfig: {},
};
