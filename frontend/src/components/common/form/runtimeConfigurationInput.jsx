// @ts-nocheck
import React from "react";
import PropTypes from "prop-types";

import { ContentSection } from "@certego/certego-ui";

import { markdownToHtml } from "../markdownToHtml";
import { ScanTypes } from "../../../constants/advancedSettingsConst";
import { JsonEditor } from "../JsonEditor";

export function runtimeConfigurationParam(
  formik,
  analyzersStored,
  connectorsStored,
  visualizersStored,
  pivotsStored,
) {
  function calculateStore(pluginType) {
    switch (pluginType) {
      case "analyzers":
        return analyzersStored;
      case "connectors":
        return connectorsStored;
      case "visualizers":
        return visualizersStored;
      case "pivots":
        return pivotsStored;
      default:
        return [];
    }
  }

  console.debug("EditRuntimeConfiguration - formik:");
  console.debug(formik);

  const isScanPage = formik.values.analysisOptionValues || false;

  // IMPORTANT: We want to group the plugins in the categories (analyzers, connectors, etc...)
  const selectedPluginsInFormik = { analyzers: {}, connectors: {} };
  const selectedPluginsParams = { analyzers: {}, connectors: {} };
  const editableConfig = { analyzers: {}, connectors: {} };

  // case A: scan page
  if (isScanPage) {
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
  } else {
    // case B: create new playbook (no plugin selected)
    if (
      formik.values.analyzers.length === 0 &&
      formik.values.connectors.length === 0 &&
      formik.values.pivots.length === 0 &&
      formik.values.visualizers.length === 0
    ) {
      console.debug("Runtime config - create new playbook");
      selectedPluginsParams.pivots = {};
      selectedPluginsParams.visualizers = {};
      editableConfig.pivots = {};
      editableConfig.visualizers = {};
      return [selectedPluginsParams, editableConfig];
    }
    // case C:  edit playbook config
    ["analyzers", "connectors", "visualizers", "pivots"].forEach(
      (pluginType) => {
        selectedPluginsInFormik[pluginType] =
          formik.values[pluginType]?.map((plugin) => plugin.value) || [];
      },
    );
  }

  console.debug("EditRuntimeConfiguration - selectedPluginsInFormik:");
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

  console.debug("EditRuntimeConfiguration - selectedPluginsParams:");
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

  console.debug("EditRuntimeConfiguration - editableConfig:");
  console.debug(editableConfig);

  return [selectedPluginsParams, editableConfig];
}

export function saveRuntimeConfiguration(
  formik,
  jsonInput,
  selectedPluginsParams,
  editableConfig,
) {
  // we only want to save configuration against plugins whose params dict is not empty or was modified
  if (Object.keys(jsonInput).length > 0 && jsonInput !== undefined) {
    let jsonInputToSave = {};
    if (jsonInput?.jsObject) jsonInputToSave = jsonInput?.jsObject;
    else jsonInputToSave = jsonInput;

    const runtimeConfig = {};
    Object.keys(selectedPluginsParams).forEach((pluginType) => {
      runtimeConfig[pluginType] = Object.entries(
        jsonInputToSave[pluginType],
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
    console.debug("EditRuntimeConfiguration - saved runtimeConfig:");
    console.debug(runtimeConfig);
    formik.setFieldValue("runtime_configuration", runtimeConfig, false);
  }
}

// components
export function EditRuntimeConfiguration(props) {
  const { setJsonInput, selectedPluginsParams, editableConfig } = props;

  return (
    <div className="d-flex-start-start bg-body pt-3">
      <ContentSection
        className="bg-darker"
        id="edit_runtime_configuration-section"
        style={{ width: "45%", height: "590px" }}
      >
        <small className="text-muted">
          Note: Edit this only if you know what you are doing!
        </small>
        <JsonEditor
          id="runtime_configuration"
          initialJsonData={editableConfig}
          onChange={setJsonInput}
          height="95%"
          width="100%"
        />
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
    </div>
  );
}

EditRuntimeConfiguration.propTypes = {
  setJsonInput: PropTypes.func.isRequired,
  selectedPluginsParams: PropTypes.object.isRequired,
  editableConfig: PropTypes.object.isRequired,
};
