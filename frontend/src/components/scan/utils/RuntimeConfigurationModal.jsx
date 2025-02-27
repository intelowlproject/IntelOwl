// @ts-nocheck
import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Button } from "reactstrap";

import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import {
  EditRuntimeConfiguration,
  runtimeConfigurationParam,
  saveRuntimeConfiguration,
} from "../../common/form/runtimeConfigurationInput";

// constants
const stateSelector = (state) => [
  state.analyzers,
  state.connectors,
  state.visualizers,
  state.pivots,
];

// components
export function RuntimeConfigurationModal(props) {
  const { isOpen, toggle, formik, ...rest } = props;

  const [jsonInput, setJsonInput] = React.useState({});

  console.debug(jsonInput);

  const [analyzers, connectors, visualizers, pivots] =
    usePluginConfigurationStore(stateSelector);

  const [selectedPluginsParams, editableConfig] = runtimeConfigurationParam(
    formik,
    analyzers,
    connectors,
    visualizers,
    pivots,
  );

  const saveAndCloseModal = () => {
    saveRuntimeConfiguration(
      formik,
      jsonInput,
      selectedPluginsParams,
      editableConfig,
    );
    toggle();
  };

  return (
    <Modal
      autoFocus
      zIndex="1050"
      size="xl"
      isOpen={isOpen}
      toggle={toggle}
      scrollable
      backdrop="static"
      labelledBy="Edit Runtime Configuration"
      {...rest}
    >
      <ModalHeader className="bg-tertiary" toggle={toggle}>
        Edit Runtime Configuration
      </ModalHeader>
      <ModalBody
        className="d-flex-column bg-body"
        id="edit_runtime_configuration-ModalBody"
      >
        <EditRuntimeConfiguration
          setJsonInput={setJsonInput}
          selectedPluginsParams={selectedPluginsParams}
          editableConfig={editableConfig}
        />
        <div className=" d-flex align-items-center justify-content-end">
          <Button
            onClick={toggle}
            size="sm"
            color=""
            className="btn-link text-gray"
          >
            Ignore changes & close
          </Button>
          <Button
            disabled={jsonInput?.error}
            onClick={saveAndCloseModal}
            size="sm"
            color="info"
            className="ms-2"
          >
            Save & Close
          </Button>
        </div>
      </ModalBody>
    </Modal>
  );
}

RuntimeConfigurationModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  toggle: PropTypes.func.isRequired,
  formik: PropTypes.object.isRequired,
};
