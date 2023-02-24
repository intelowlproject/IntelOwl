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

const ANALYZER = "1";
const CONNECTOR = "2";

// eslint-disable-next-line no-unused-vars
const PARAMETER = "1";
const SECRET = "2";

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

function filterEmptyData(plugins, dataName) {
  return Object.keys(plugins)
    .filter(
      (pluginName) =>
        plugins[pluginName][dataName] &&
        Object.keys(plugins[pluginName][dataName]).length > 0
    )
    .reduce(
      (filteredPlugins, key) =>
        Object.assign(filteredPlugins, { [key]: plugins[key] }),
      {}
    );
}

export function PluginData({
  entryFilter,
  additionalEntryData,
  dataUri,
  createPluginData,
  updatePluginData,
  deletePluginData,
  dataName,
  valueType,
  editable,
}) {
  const [
    analyzers,
    connectors,
    retrieveAnalyzersConfiguration,
    retrieveConnectorsConfiguration,
  ] = usePluginConfigurationStore((state) => [
    filterEmptyData(state.analyzersJSON, dataName),
    filterEmptyData(state.connectorsJSON, dataName),
    state.retrieveAnalyzersConfiguration,
    state.retrieveConnectorsConfiguration,
  ]);

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
          if (res.type === ANALYZER) {
            plugins = analyzers;
          } else if (res.type === CONNECTOR) {
            plugins = connectors;
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

  const refetchAll = () => {
    refetchPluginData();
    retrieveAnalyzersConfiguration();
    retrieveConnectorsConfiguration();
  };

  const maxPluginNameLength = Math.max(
    ...Object.keys(analyzers).map((pluginName) => pluginName.length),
    ...Object.keys(connectors).map((pluginName) => pluginName.length)
  );

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
                            if (configuration.type === "1") {
                              plugins = analyzers;
                            } else if (configuration.type === "2") {
                              plugins = connectors;
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
                              <Row className="py-2" key={`entry.${index + 0}`}>
                                <Col className="col-2">
                                  <Field
                                    as="select"
                                    className={`form-select ${disabledSuffix}`}
                                    disabled={!configuration.edit}
                                    name={`entry[${index}].type`}
                                  >
                                    <option value="">---Select Type---</option>
                                    <option value="1">Analyzer</option>
                                    <option value="2">Connector</option>
                                  </Field>
                                </Col>

                                <div className="col-auto">
                                  <Field
                                    as="select"
                                    className={`form-select ${disabledSuffix}`}
                                    disabled={!configuration.edit}
                                    name={`entry[${index}].plugin_name`}
                                  >
                                    <option value="">
                                      {"-".repeat(
                                        Math.ceil(
                                          (maxPluginNameLength - 11) / 2
                                        )
                                      )}
                                      Select Plugin Name
                                      {"-".repeat(
                                        Math.ceil(
                                          (maxPluginNameLength - 11) / 2
                                        )
                                      )}
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
                                        SECRET && !configuration.edit
                                        ? "**********"
                                        : configuration.value
                                    }
                                  />
                                </Col>
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
                                        if (
                                          plugins[newConfiguration.plugin_name]
                                            .params[newConfiguration.attribute]
                                            ?.type === "str"
                                        ) {
                                          newConfiguration.value =
                                            JSON.stringify(
                                              newConfiguration.value
                                            );
                                        }
                                        if (newConfiguration.create)
                                          createPluginData(
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
                                          updatePluginData(
                                            newConfiguration,
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
                                        deletePluginData(configuration.id).then(
                                          () => {
                                            remove(index);
                                            refetchAll();
                                          }
                                        );
                                    }}
                                  >
                                    <BsFillTrashFill />
                                  </Button>
                                ) : null}
                              </Row>
                            );
                          })
                        : null}
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
  createPluginData: PropTypes.func.isRequired,
  updatePluginData: PropTypes.func.isRequired,
  deletePluginData: PropTypes.func.isRequired,
  dataName: PropTypes.string.isRequired,
  valueType: PropTypes.string.isRequired,
  editable: PropTypes.bool.isRequired,
};

PluginData.defaultProps = {
  entryFilter: (x) => x,
};
