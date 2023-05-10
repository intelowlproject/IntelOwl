import { addToast, useAxiosComponentLoader } from "@certego/certego-ui";
import { Field, FieldArray, Form, Formik } from "formik";
import PropTypes from "prop-types";
import React from "react";
import {
  BsFillCheckSquareFill,
  BsFillPencilFill,
  BsFillPlusCircleFill,
  BsFillTrashFill,
} from "react-icons/bs";
import { MdCancel } from "react-icons/md";
import { Button, Col, FormGroup, Input, Row } from "reactstrap";
import { usePluginConfigurationStore } from "../../stores";
import { pluginType, configType } from "../../constants/constants";

import {
  createCustomConfig,
  deleteCustomConfig,
  updateCustomConfig,
} from "../me/config/api";

function isJSON(str) {
  try {
    JSON.parse(str); // && !!str
  } catch (e) {
    return false;
  }
  return true;
}

function isValidEntry(item, valueType) {
  if (!item.type) {
    addToast("Invalid entry!", "Please select a type", "danger", true);
    return false;
  }
  if (!item.plugin_name) {
    addToast("Invalid entry!", "Please select a plugin", "danger", true);
    return false;
  }
  if (!item.attribute) {
    addToast("Invalid entry!", "Please select an attribute", "danger", true);
    return false;
  }
  if (!["str", "json"].includes(valueType))
    console.error(`Invalid value type: ${valueType}`);
  return true;
}

/**
 * Filter the plugins without a configuration: with empty params or secrets (choosen on dataName param)
 *
 * @param {Array.Object} plugins List of plugins
 * @param {string} dataName name of the plugin's field with the configurations (params/secrets)
 * @returns
 */
function filterEmptyData(plugins, dataName) {
  return plugins
    .filter(
      (plugin) => plugin[dataName] && Object.keys(plugin[dataName]).length > 0
    )
    .reduce(
      (filteredPlugins, plugin) =>
        Object.assign(filteredPlugins, { [plugin.name]: plugin }),
      {}
    );
}

/**
 * Component with the plugins configurations
 *
 * @param {function} entryFilter function used to filter the custom config from the backend (show only configs or only secrets)
 * @param {object} additionalEntryData contains a value used to show the values of the configuration or hide (***) in case of secrets
 * @param {string} dataUri uri of the API with the custom configs
 * @param {string} dataName name of the plugin's field with the configurations (params/secrets)
 * @param {string} valueType value used in the validation of the config
 * @param {boolean} editable flag used to allow the user to view the config (used by the organization to hide the component to not allowed users)
 * @returns {React.Component} editable table with the plugins configurations
 */
export function PluginData({
  entryFilter,
  additionalEntryData,
  dataUri,
  dataName,
  valueType,
  editable,
}) {
  const [
    analyzers,
    connectors,
    visualizers,
    retrieveAnalyzersConfiguration,
    retrieveConnectorsConfiguration,
    retrieveVisualizersConfiguration,
  ] = usePluginConfigurationStore((state) => [
    filterEmptyData(state.analyzers, dataName),
    filterEmptyData(state.connectors, dataName),
    filterEmptyData(state.visualizers, dataName),
    state.retrieveAnalyzersConfiguration,
    state.retrieveConnectorsConfiguration,
    state.retrieveVisualizersConfiguration,
  ]);

  // download the configs
  const [respData, Loader, refetchPluginData] = useAxiosComponentLoader(
    {
      url: dataUri,
    },
    (resp) => {
      let pluginConfigs = entryFilter(resp);
      if (Object.keys(analyzers).length > 0) {
        pluginConfigs = pluginConfigs.map((pluginConfig) => {
          const res = pluginConfig;
          let plugins;
          if (res.type === pluginType.ANALYZER) {
            plugins = analyzers;
          } else if (res.type === pluginType.CONNECTOR) {
            plugins = connectors;
          } else if (res.type === pluginType.VISUALIZER) {
            plugins = visualizers;
          } else {
            console.error(`Invalid type: ${res.type}`);
          }
          if (plugins[res.plugin_name].params[res.attribute]?.type === "str") {
            res.value = isJSON(res.value) ? JSON.parse(res.value) : res.value;
          }
          return res;
        });
      }
      return pluginConfigs;
    }
  );

  // download the configs and again the analyzers with the update values
  const refetchAll = () => {
    refetchPluginData();
    retrieveAnalyzersConfiguration();
    retrieveConnectorsConfiguration();
    retrieveVisualizersConfiguration();
  };

  // form/"table" with the config
  return (
    <Loader
      render={() => (
        <Formik initialValues={{ entry: respData }} onSubmit={null}>
          {({ values: configurations, setFieldValue }) => (
            <Form>
              <FieldArray name="entry">
                {({ remove, push }) => (
                  <FormGroup row>
                    <Col>
                      {configurations.entry && configurations.entry.length > 0
                        ? configurations.entry.map((configuration, index) => {
                            let plugins = {};
                            let attributeList = [];
                            let placeholder = "";
                            if (configuration.type === pluginType.ANALYZER) {
                              plugins = analyzers;
                            } else if (
                              configuration.type === pluginType.CONNECTOR
                            ) {
                              plugins = connectors;
                            } else if (
                              configuration.type === pluginType.VISUALIZER
                            ) {
                              plugins = visualizers;
                            }

                            if (
                              configuration.plugin_name &&
                              plugins[configuration.plugin_name]
                            )
                              attributeList = Object.keys(
                                plugins[configuration.plugin_name][dataName]
                              );
                            if (
                              attributeList.length > 0 &&
                              configuration.attribute &&
                              plugins[configuration.plugin_name][dataName][
                                configuration.attribute
                              ]
                            ) {
                              const { type } =
                                plugins[configuration.plugin_name][dataName][
                                  configuration.attribute
                                ];
                              if (type === "str") placeholder = "string";
                              else if (type === "int") placeholder = "1234";
                              else if (type === "float") placeholder = "12.34";
                              else if (type === "bool") placeholder = "true";
                              else if (type === "json")
                                placeholder = '{"key": "value"}';
                              else if (type === "list") placeholder = "[...]";
                              else if (type === "dict") placeholder = "{...}";
                              // Unknown type
                              else placeholder = "???????";
                            }
                            const disabledSuffix = configuration.edit
                              ? " input-dark "
                              : " disabled text-dark input-secondary ";

                            return (
                              /* Row with a config: each row have five columns:
                              plugin type selection, plugin selection, param selection, param value, buttons to edit/save/delete
                              */
                              <Row className="py-2" key={`entry.${index + 0}`}>
                                {/* col for the plugin type selection */}
                                <Col className="col-2">
                                  <Field
                                    as="select"
                                    className={`form-select ${disabledSuffix}`}
                                    disabled={!configuration.edit}
                                    name={`entry[${index}].type`}
                                  >
                                    <option value="">---Select Type---</option>
                                    <option value={pluginType.ANALYZER}>
                                      Analyzer
                                    </option>
                                    <option value={pluginType.CONNECTOR}>
                                      Connector
                                    </option>
                                    <option value={pluginType.VISUALIZER}>
                                      Visualizer
                                    </option>
                                  </Field>
                                </Col>
                                {/* col for the plugin selection */}
                                <div className="col-auto">
                                  <Field
                                    as="select"
                                    className={`form-select ${disabledSuffix}`}
                                    disabled={!configuration.edit}
                                    name={`entry[${index}].plugin_name`}
                                  >
                                    <option value="">
                                      ---Select Plugin Name---
                                    </option>
                                    {Object.values(plugins).map(
                                      (pluginElement) => (
                                        <option
                                          value={pluginElement.name}
                                          key={pluginElement.name}
                                        >
                                          {pluginElement.name}
                                        </option>
                                      )
                                    )}
                                  </Field>
                                </div>
                                {/* col for the attribute selection */}
                                <Col>
                                  <Field
                                    as="select"
                                    className={`form-select ${disabledSuffix}`}
                                    disabled={!configuration.edit}
                                    name={`entry[${index}].attribute`}
                                  >
                                    <option value="">
                                      ---Select Attribute---
                                    </option>
                                    {attributeList.map((attribute) => (
                                      <option value={attribute} key={attribute}>
                                        {attribute}
                                      </option>
                                    ))}
                                  </Field>
                                </Col>
                                {/* col for the attribute value */}
                                <Col>
                                  <Field
                                    as={Input}
                                    type="text"
                                    name={`entry.${index}.value`}
                                    className={disabledSuffix}
                                    disabled={!configuration.edit}
                                    placeholder={placeholder}
                                    value={
                                      additionalEntryData.config_type ===
                                        configType.SECRET && !configuration.edit
                                        ? "**********"
                                        : configuration.value
                                    }
                                  />
                                </Col>
                                {/* col with the buttons to save/delete/modify the config */}
                                {editable ? (
                                  <Button
                                    color="primary"
                                    className="mx-2 rounded-1 text-larger col-auto"
                                    onClick={() => {
                                      if (configuration.edit) {
                                        if (
                                          !isValidEntry(
                                            configuration,
                                            valueType
                                          )
                                        )
                                          return;
                                        const newConfiguration = {
                                          ...configuration,
                                          ...additionalEntryData,
                                        };
                                        if (newConfiguration.create)
                                          createCustomConfig(
                                            newConfiguration
                                          ).then(() => {
                                            setFieldValue(
                                              `entry.${index}.edit`,
                                              false
                                            );
                                            setFieldValue(
                                              `entry.${index}.create`,
                                              false
                                            );
                                            refetchAll();
                                          });
                                        else
                                          updateCustomConfig(
                                            newConfiguration.value,
                                            newConfiguration.id
                                          ).then(() => {
                                            setFieldValue(
                                              `entry.${index}.edit`,
                                              false
                                            );
                                            refetchAll();
                                          });
                                      } else
                                        setFieldValue(
                                          `entry.${index}.edit`,
                                          true
                                        );
                                    }}
                                  >
                                    {configuration.edit ? (
                                      <BsFillCheckSquareFill />
                                    ) : (
                                      <BsFillPencilFill />
                                    )}
                                  </Button>
                                ) : null}
                                {configuration.edit && !configuration.create ? (
                                  <Button
                                    color="primary"
                                    className="mx-2 rounded-1 text-larger col-auto"
                                    onClick={refetchAll}
                                  >
                                    <MdCancel />
                                  </Button>
                                ) : null}
                                {editable ? (
                                  <Button
                                    color="primary"
                                    className="mx-2 rounded-1 text-larger col-auto"
                                    onClick={() => {
                                      if (configuration.create) remove(index);
                                      else
                                        deleteCustomConfig(
                                          configuration.id
                                        ).then(() => {
                                          remove(index);
                                          refetchAll();
                                        });
                                    }}
                                  >
                                    <BsFillTrashFill />
                                  </Button>
                                ) : null}
                              </Row>
                            );
                          })
                        : null}
                      {/* Additional row with the button to add a new row/config */}
                      {editable ? (
                        <Row className="mb-2 mt-0 pt-0">
                          <Button
                            color="primary"
                            size="sm"
                            className="my-2 mx-auto rounded-1 col-auto"
                            onClick={() =>
                              push({
                                create: true,
                                edit: true,
                              })
                            }
                          >
                            <BsFillPlusCircleFill /> Add new entry
                          </Button>
                        </Row>
                      ) : null}
                    </Col>
                  </FormGroup>
                )}
              </FieldArray>
            </Form>
          )}
        </Formik>
      )}
    />
  );
}

PluginData.propTypes = {
  entryFilter: PropTypes.func,
  additionalEntryData: PropTypes.object.isRequired,
  dataUri: PropTypes.string.isRequired,
  dataName: PropTypes.string.isRequired,
  valueType: PropTypes.string.isRequired,
  editable: PropTypes.bool.isRequired,
};

PluginData.defaultProps = {
  entryFilter: (x) => x,
};
