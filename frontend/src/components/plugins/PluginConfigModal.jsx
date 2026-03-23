import React from "react";
import { Modal, ModalHeader, ModalBody, UncontrolledTooltip } from "reactstrap";
import PropTypes from "prop-types";
import { MdInfoOutline } from "react-icons/md";
import { Link } from "react-router-dom";

import { PluginsTypes } from "../../constants/pluginConst";
import { AnalyzerConfigForm } from "./forms/AnalyzerConfigForm";
import { PivotConfigForm } from "./forms/PivotConfigForm";
import { PlaybookConfigForm } from "./forms/PlaybookConfigForm";
import { PluginConfigContainer } from "./PluginConfigContainer";
import { INTELOWL_DOCS_URL } from "../../constants/environment";

export function PluginConfigModal({
  pluginConfig,
  pluginType,
  toggle,
  isOpen,
}) {
  console.debug("PluginConfigModal rendered!");

  let isEditing = Object.keys(pluginConfig).length > 0;
  const isBasicAnalyzer =
    pluginType === PluginsTypes.ANALYZER &&
    pluginConfig.python_module ===
      "basic_observable_analyzer.BasicObservableAnalyzer";

  let title = (
    <div>
      Plugin config
      <MdInfoOutline
        id="pluginConfig_infoicon"
        fontSize="16"
        className="ms-2"
      />
      <UncontrolledTooltip
        trigger="hover"
        target="pluginConfig_infoicon"
        placement="right"
        fade={false}
        autohide={false}
        innerClassName="p-2 text-start text-nowrap md-fit-content"
      >
        Each plugin could have one or more parameters available to be configured
        to customize the plugin behavior.
        <br />
        For more info check the{" "}
        <Link
          to={`${INTELOWL_DOCS_URL}IntelOwl/usage/#parameters`}
          target="_blank"
        >
          official doc.
        </Link>
      </UncontrolledTooltip>
    </div>
  );
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
    // save as a playbook button -> create new playbook
    if (isEditing && !Object.keys(pluginConfig).includes("name")) {
      isEditing = false;
    }
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
      backdrop="static"
      labelledBy="Plugin config modal"
      isOpen={isOpen}
      style={{ minWidth: "70%" }}
      toggle={() => toggle(false)}
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
