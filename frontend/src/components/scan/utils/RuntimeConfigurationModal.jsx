// @ts-nocheck
import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Button } from "reactstrap";

import { ContentSection, CustomJsonInput } from "@certego/certego-ui";

import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { markdownToHtml } from "../../common/markdownToHtml";
import { ScanTypes } from "../../../constants/advancedSettingsConst";

// constants
const stateSelector = (state) => [state.analyzers, state.connectors];

// components
export function RuntimeConfigurationModal(props) {
  const { isOpen, toggle, formik, ...rest } = props;

  const [jsonInput, setJsonInput] = React.useState({});

  const [analyzers, connectors] = usePluginConfigurationStore(stateSelector);

  console.debug("RuntimeConfigurationModal - formik:");
  console.debug(formik);

  const selectedAnalyzers =
    formik.values.analysisOptionValues === ScanTypes.analyzers_and_connectors
      ? formik.values.analyzers.map((x) => x.value)
      : formik.values.playbook.analyzers;
  const selectedConnectors =
    formik.values.analysisOptionValues === ScanTypes.analyzers_and_connectors
      ? formik.values.connectors.map((x) => x.value)
      : formik.values.playbook.connectors;

  // Extract selected plugin params (with description and type used by the side section)
  // IMPORTANT: We want to group the plugins in the categories (analyzers, connectors, etc...)
  const combinedParamsMap = {};
  if (
    formik.values.analysisOptionValues === ScanTypes.playbooks &&
    Object.keys(formik.values.runtime_configuration)
  ) {
    Object.keys(formik.values.runtime_configuration).forEach((key) => {
      combinedParamsMap[key] = {};
    });
  }
  combinedParamsMap.analyzers = {
    // for each selected analyzer we extract the config and append it to the other configs
    ...selectedAnalyzers.reduce(
      (configurationsToDisplay, analyzerName) => ({
        // in this way we add to the new object the previous object
        ...configurationsToDisplay,
        // find the params of the selected analyzer and add it
        [analyzerName]: analyzers.find(
          (analyzer) => analyzer.name === analyzerName,
        )?.params,
      }),
      {},
    ),
  };
  // same for the connectors
  combinedParamsMap.connectors = {
    ...selectedConnectors.reduce(
      (configurationsToDisplay, connectorName) => ({
        ...configurationsToDisplay,
        [connectorName]: connectors.find(
          (connector) => connector.name === connectorName,
        )?.params,
      }),
      {},
    ),
  };
  console.debug("RuntimeConfigurationModal - combinedParamsMap:");
  console.debug(combinedParamsMap);

  // Iterate each plugin and for each param extract the value
  const defaultNameParamsMap = {};
  Object.keys(combinedParamsMap).forEach((key) => {
    defaultNameParamsMap[key] = Object.entries(combinedParamsMap[key]).reduce(
      (generalConfig, [pluginName, pluginParams]) => ({
        ...generalConfig,
        // For each param (dict) extract the value of the "value" key
        [pluginName]: Object.entries(pluginParams).reduce(
          (singlePluginConfig, [paramName, { value: paramValue }]) => ({
            ...singlePluginConfig,
            [paramName]: paramValue,
          }),
          {},
        ),
      }),
      {},
    );
  });
  console.debug("RuntimeConfigurationModal - defaultNameParamsMap:");
  console.debug(defaultNameParamsMap);

  /* this is the dict shown when the modal is open: load the default params and the previous saved config
    (in case the user update the config, save and close and reopen the modal)
  */
  const editableConfig = {};
  Object.keys(combinedParamsMap).forEach((key) => {
    editableConfig[key] = {
      ...defaultNameParamsMap[key],
      ...(formik.values.runtime_configuration[key] || {}),
    };
  });
  console.debug("RuntimeConfigurationModal - editableConfig:");
  console.debug(editableConfig);

  const saveAndCloseModal = () => {
    // we only want to save configuration against plugins whose params dict is not empty or was modified
    if (jsonInput?.jsObject) {
      const runtimeCfg = {};
      Object.keys(combinedParamsMap).forEach((key) => {
        runtimeCfg[key] = Object.entries(jsonInput.jsObject[key]).reduce(
          (acc, [name, params]) =>
            // we cannot exclude empty dict or it could erase "connectors: {}" and generate an error
            JSON.stringify(defaultNameParamsMap[name]) !==
            JSON.stringify(params)
              ? { ...acc, [name]: params }
              : acc,
          {},
        );
      });
      console.debug("RuntimeConfigurationModal - saved runtimeCfg:");
      console.debug(runtimeCfg);
      formik.setFieldValue("runtime_configuration", runtimeCfg, false);
    }
    toggle();
  };

  return (
    <Modal
      autoFocus
      zIndex="1050"
      size="xl"
      isOpen={isOpen}
      toggle={toggle}
      keyboard={false}
      scrollable
      backdrop="static"
      labelledBy="Edit Runtime Configuration"
      {...rest}
    >
      <ModalHeader className="bg-tertiary" toggle={toggle}>
        Edit Runtime Configuration
      </ModalHeader>
      <ModalBody className="d-flex-start-start bg-body">
        <ContentSection
          className="bg-darker"
          style={{ width: "45%", maxHeight: "590px", overflowY: "auto" }}
        >
          <small className="text-muted">
            Note: Edit this only if you know what you are doing!
          </small>
          <CustomJsonInput
            id="edit_runtime_configuration-modal"
            placeholder={editableConfig}
            onChange={setJsonInput}
            height="500px"
            width="450px"
          />
          <div className="mt-2 d-flex align-items-center justify-content-end">
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
        </ContentSection>
        {/* lateral menu with the type and description of each param */}
        <ContentSection
          className="ms-2 bg-darker"
          style={{ width: "60%", maxHeight: "590px", overflowY: "auto" }}
        >
          {Object.keys(combinedParamsMap)
            .sort()
            .map((key) => (
              <div>
                {Object.keys(combinedParamsMap[key]).length > 0 ? (
                  <h5 className="text-accent">{key.toUpperCase()}:</h5>
                ) : (
                  <h5 className="text-accent">
                    {key.toUpperCase()}:{" "}
                    <small className="text-muted fst-italic"> null</small>
                  </h5>
                )}
                {Object.entries(combinedParamsMap[key]).map(
                  ([name, params]) => (
                    <div key={`editruntimeconf__${name}`}>
                      <h6 className="text-secondary px-3">{name}</h6>
                      {Object.entries(params).length ? (
                        <ul className="px-5">
                          {Object.entries(params).map(([pName, pObj]) => (
                            <li key={`editruntimeconf__${name}__${pName}`}>
                              <span className="text-pre">{pName}</span>
                              &nbsp;
                              <em className="text-muted">({pObj.type})</em>
                              <dd className="text-muted">
                                {markdownToHtml(pObj.description)}
                              </dd>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <span className="text-muted fst-italic px-4">null</span>
                      )}
                    </div>
                  ),
                )}
              </div>
            ))}
        </ContentSection>
      </ModalBody>
    </Modal>
  );
}

RuntimeConfigurationModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  toggle: PropTypes.func.isRequired,
  formik: PropTypes.object.isRequired,
};
