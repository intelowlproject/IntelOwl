import React from "react";
import { Modal, ModalHeader, ModalBody } from "reactstrap";
import PropTypes from "prop-types";

import { PluginsTypes } from "../../constants/pluginConst";
import { AnalyzerConfigForm } from "./forms/AnalyzerConfigForm";
import { PivotConfigForm } from "./forms/PivotConfigForm";
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
  if (isBasicAnalyzer) {
    title = "Edit analyzer config";
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
      <ModalBody className="m-2">
        {/* Edit plugin config - DEFAULT */}
        {isEditing &&
          !(isBasicAnalyzer || pluginType === PluginsTypes.PIVOT) && (
            <PluginConfigContainer
              pluginName={pluginConfig.name}
              pluginType={pluginType}
            />
          )}
        {/* Create/Edit basic analyzer */}
        {(isBasicAnalyzer ||
          (pluginType === PluginsTypes.ANALYZER && !isEditing)) && (
          <AnalyzerConfigForm
            analyzerConfig={pluginConfig}
            toggle={toggle}
            isEditing
          />
        )}
        {/* Create/Edit basic pivot */}
        {pluginType === PluginsTypes.PIVOT && (
          <PivotConfigForm pivotConfig={pluginConfig} toggle={toggle} />
        )}
      </ModalBody>
    </Modal>
  );
}

PluginConfigModal.propTypes = {
  pluginConfig: PropTypes.object,
  pluginType: PropTypes.oneOf(["analyzer", "connector", "ingestor", "pivot"])
    .isRequired,
  toggle: PropTypes.func.isRequired,
  isOpen: PropTypes.bool.isRequired,
};

PluginConfigModal.defaultProps = {
  pluginConfig: {},
};
