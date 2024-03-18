// @ts-nocheck
import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Button } from "reactstrap";

import { ContentSection, CustomJsonInput } from "@certego/certego-ui";

import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { markdownToHtml } from "../../common/markdownToHtml";
import { ScanTypes } from "../../../constants/advancedSettingsConst";

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

  const [analyzers, connectors, visualizers, pivots] =
    usePluginConfigurationStore(stateSelector);

  function calculateStore(pluginType) {
    switch (pluginType) {
      case "analyzers":
        return analyzers;
      case "connectors":
        return connectors;
      case "visualizers":
        return visualizers;
      case "pivots":
        return pivots;
      default:
        return [];
    }
  }

  console.debug("RuntimeConfigurationModal - formik:");
  console.debug(formik);

  // IMPORTANT: We want to group the plugins in the categories (analyzers, connectors, etc...)
  const selectedPluginsInFormik = { analyzers: {}, connectors: {} };
  const selectedPluginsParams = { analyzers: {}, connectors: {} };
  const editableConfig = { analyzers: {}, connectors: {} };

  // case 1: analysis with analyzers/connectors
  if (
    formik.values.analysisOptionValues === ScanTypes.analyzers_and_connectors
  ) {
    selectedPluginsInFormik.analyzers = formik.values.analyzers.map(
      (analyzer) => analyzer.value,
    );
    selectedPluginsInFormik.connectors = formik.values.connectors.map(
      (connector) => connector.value,
    );
  }

  // case 2: analysis with playbooks
  if (formik.values.analysisOptionValues === ScanTypes.playbooks) {
    Object.keys(formik.values.runtime_configuration).forEach((pluginType) => {
      selectedPluginsInFormik[pluginType] =
        formik.values.playbook[pluginType] || [];
    });
  }

  console.debug("RuntimeConfigurationModal - selectedPluginsInFormik:");
  console.debug(selectedPluginsInFormik);

  // Extract plugin default params from the store.
  // Description and type are used in the side section.
  Object.keys(selectedPluginsInFormik).forEach((pluginType) => {
    selectedPluginsParams[pluginType] = {
      // for each selected plugin we extract the config and append it to the other configs
      ...selectedPluginsInFormik[pluginType].reduce(
        (configurationsToDisplay, pluginName) => ({
          // in this way we add to the new object the previous object
          ...configurationsToDisplay,
          // find the params in the store of the selected plugin and add it
          [pluginName]: calculateStore(pluginType).find(
            (plugin) => plugin.name === pluginName,
          )?.params,
        }),
        {},
      ),
    };
  });

  console.debug("RuntimeConfigurationModal - selectedPluginsParams:");
  console.debug(selectedPluginsParams);

  /* this is the dict shown when the modal is open: load the default params and the previous saved config
    (in case the user update the config, save and close and reopen the modal)
    We want to show data in this format:
    {
      pluginType: {
        pluginName: {
          paramName: paramValue,
        },
      },
    }
  */
  Object.keys(selectedPluginsInFormik).forEach((pluginType) => {
    editableConfig[pluginType] = {};
    // for each plugin extract name and default params
    Object.entries(selectedPluginsParams[pluginType]).forEach(
      ([pluginName, pluginParams]) => {
        // add empty dict in editableConfig for plugin that have not params
        editableConfig[pluginType][pluginName] = {};
        // for each param (dict) extract the value of the "value" key
        Object.entries(pluginParams)
          .filter(([_, { value: paramValue }]) => paramValue)
          .forEach(([paramName, { value: paramValue }]) => {
            editableConfig[pluginType][pluginName][paramName] = paramValue;
          });
      },
    );
    // override config saved in formik
    editableConfig[pluginType] = {
      ...editableConfig[pluginType],
      ...(formik.values.runtime_configuration[pluginType] || {}),
    };
  });

  console.debug("RuntimeConfigurationModal - editableConfig:");
  console.debug(editableConfig);

  const saveAndCloseModal = () => {
    // we only want to save configuration against plugins whose params dict is not empty or was modified
    if (jsonInput?.jsObject) {
      const runtimeCfg = {};
      Object.keys(selectedPluginsParams).forEach((pluginType) => {
        runtimeCfg[pluginType] = Object.entries(
          jsonInput.jsObject[pluginType],
        ).reduce(
          (acc, [pluginName, pluginParams]) =>
            // we cannot exclude empty dict or it could erase "connectors: {}" and generate an error
            JSON.stringify(editableConfig[pluginType][pluginName]) !==
            JSON.stringify(pluginParams)
              ? { ...acc, [pluginName]: pluginParams }
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
      <ModalBody
        className="d-flex-start-start bg-body"
        id="edit_runtime_configuration-ModalBody"
      >
        <ContentSection
          className="bg-darker"
          id="edit_runtime_configuration-section"
          style={{ width: "45%", maxHeight: "590px", overflowY: "auto" }}
        >
          <small className="text-muted">
            Note: Edit this only if you know what you are doing!
          </small>
          <CustomJsonInput
            id="edit_runtime_configuration-modal"
            placeholder={editableConfig}
            onChange={setJsonInput}
            /* waitAfterKeyPress=1000 is the default value and we cannot change it:
              with this value (or higher) in case the user press "save & close" too fast it doesn't take changes.
              If we decrease it (min allowed 100) we don't have this problems, but it's not possible to edit:
              The library auto refresh and move the cursor too fast to make it editable.
            */
            waitAfterKeyPress={1000}
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
          {Object.keys(selectedPluginsParams)
            .sort()
            .map((key) => (
              <div>
                {Object.keys(selectedPluginsParams[key]).length > 0 ? (
                  <h5 className="text-accent">{key.toUpperCase()}:</h5>
                ) : (
                  <h5 className="text-accent">
                    {key.toUpperCase()}:{" "}
                    <small className="text-muted fst-italic"> null</small>
                  </h5>
                )}
                {Object.entries(selectedPluginsParams[key]).map(
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
