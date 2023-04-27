// @ts-nocheck
import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Button } from "reactstrap";

import { ContentSection, CustomJsonInput } from "@certego/certego-ui";

import usePluginConfigurationStore from "../../../stores/usePluginConfigurationStore";
import markdownToHtml from "../../common/markdownToHtml";

// constants
const stateSelector = (state) => [state.analyzers, state.connectors];

// components
export default function RuntimeConfigurationModal(props) {
  const { isOpen, toggle, formik, ...rest } = props;

  const [jsonInput, setJsonInput] = React.useState({});

  const [analyzers, connectors] = usePluginConfigurationStore(stateSelector);

  console.debug("RuntimeConfigurationModal - formik:");
  console.debug(formik);

  // Extract selected plugin params (with description and type used by the side section)
  const combinedParamsMap = React.useMemo(
    () => ({
      // for each selected analyzer we extract the config and append it to the other configs
      ...formik.values.analyzers.reduce(
        // { value: analyzerName } extract the "value" field from the formik values and allow to use it as analyzerName
        (configurationsToDisplay, { value: analyzerName }) => ({
          // in this way we add to the new object the previous object
          ...configurationsToDisplay,
          // find the config of the selected analyzer and add it
          [analyzerName]: analyzers.find(
            (analyzer) => analyzer.name === analyzerName
          )?.params,
        }),
        {}
      ),
      // same for the connectors
      ...formik.values.connectors.reduce(
        (configurationsToDisplay, { value: connectorName }) => ({
          ...configurationsToDisplay,
          [connectorName]: connectors.find(
            (connector) => connector.name === connectorName
          )?.params,
        }),
        {}
      ),
    }),
    [formik.values.analyzers, formik.values.connectors, analyzers, connectors]
  );

  console.debug("RuntimeConfigurationModal - combinedParamsMap:");
  console.debug(combinedParamsMap);

  // Iterate each plugin and for each param extract the value
  const defaultNameParamsMap = React.useMemo(
    () =>
      Object.entries(combinedParamsMap).reduce(
        (generalConfig, [pluginName, pluginParams]) => ({
          ...generalConfig,
          // For each param (dict) extract the value of the "value" key
          [pluginName]: Object.entries(pluginParams).reduce(
            (singlePluginConfig, [paramName, { value: paramValue }]) => ({
              ...singlePluginConfig,
              [paramName]: paramValue,
            }),
            {}
          ),
        }),
        {}
      ),
    [combinedParamsMap]
  );

  console.debug("RuntimeConfigurationModal - defaultNameParamsMap:");
  console.debug(defaultNameParamsMap);

  /* this is the dict shown when the modal is open: load the default params and the previous saved config
    (in case the user update the config, save and close and reopen the modal)

    IMPORTANT: We want to group the plugins in the categories (analyzers, etc...), it is more difficult to handle it in every variable
    so we use it only when shown to the user (UI), we need to rembeber in case we edite the params more than once we need to 
    load the data from the structure with the categories.
  */
  const editableConfig = React.useMemo(() => {
    const config = {
      ...defaultNameParamsMap,
      ...(formik.values.runtime_configuration.analyzers || {}), // previous values of analyzers (groupped by the previous editing) if present
      ...(formik.values.runtime_configuration.connectors || {}), // previous values of connectors (groupped by the previous editing) if present
    };
    const analyzerNames = analyzers.map((analyzer) => analyzer.name);
    const connectorNames = connectors.map((connector) => connector.name);
    const result = { analyzers: {}, connectors: {} };
    Object.entries(config).forEach(([configPluginName, configPluginParams]) => {
      if (analyzerNames.includes(configPluginName)) {
        result.analyzers[configPluginName] = configPluginParams;
      } else if (connectorNames.includes(configPluginName)) {
        result.connectors[configPluginName] = configPluginParams;
      }
    });
    return result;
  }, [
    analyzers,
    connectors,
    defaultNameParamsMap,
    formik.values.runtime_configuration.analyzers,
    formik.values.runtime_configuration.connectors,
  ]);

  console.debug("RuntimeConfigurationModal - editableConfig:");
  console.debug(editableConfig);

  const saveAndCloseModal = () => {
    // we only want to save configuration against plugins whose params dict is not empty or was modified
    if (jsonInput?.jsObject) {
      const runtimeCfg = Object.entries(jsonInput.jsObject).reduce(
        (acc, [name, params]) =>
          Object.keys(params).length > 0 &&
          JSON.stringify(defaultNameParamsMap[name]) !== JSON.stringify(params)
            ? { ...acc, [name]: params }
            : acc,
        {}
      );
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
        <ContentSection className="bg-darker">
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
        <ContentSection className="ms-2 bg-darker">
          {Object.entries(combinedParamsMap).map(([name, params]) => (
            <div key={`editruntimeconf__${name}`}>
              <h6 className="text-secondary">{name}</h6>
              {Object.entries(params).length ? (
                <ul>
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
                <span className="text-muted fst-italic">null</span>
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
