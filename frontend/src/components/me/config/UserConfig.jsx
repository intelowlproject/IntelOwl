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
import { Row, Col, Container, FormGroup, Input, Button } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import { usePluginConfigurationStore } from "../../../stores";
import {
  createCustomConfig,
  CUSTOM_CONFIG_URI,
  deleteCustomConfig,
  updateCustomConfig,
} from "./api";

function isJSON(str) {
  if (str === '""') return true;
  try {
    return Boolean(JSON.parse(str) && !!str);
  } catch (e) {
    return false;
  }
}

export function isValidConfig(item) {
  if (!item.type) {
    addToast("Invalid config!", "Please select a type", "danger", true);
    return false;
  }
  if (!item.plugin_name) {
    addToast("Invalid config!", "Please select a plugin", "danger", true);
    return false;
  }
  if (!item.attribute) {
    addToast("Invalid config!", "Please select an attribute", "danger", true);
    return false;
  }
  if (!isJSON(item.value)) {
    addToast(
      "Invalid config!",
      "Please enter a JSON-compliant value",
      "danger",
      true
    );
    return false;
  }
  return true;
}

export function filterEmptyParams(plugins) {
  return Object.keys(plugins)
    .filter(
      (pluginName) =>
        plugins[pluginName].params &&
        Object.keys(plugins[pluginName].params).length > 0
    )
    .reduce(
      (filteredPlugins, key) =>
        Object.assign(filteredPlugins, { [key]: plugins[key] }),
      {}
    );
}

export function Config({ configFilter, additionalConfigData }) {
  const [
    analyzers,
    connectors,
    retrieveAnalyzersConfiguration,
    retrieveConnectorsConfiguration,
  ] = usePluginConfigurationStore((state) => [
    filterEmptyParams(state.analyzersJSON),
    filterEmptyParams(state.connectorsJSON),
    state.retrieveAnalyzersConfiguration,
    state.retrieveConnectorsConfiguration,
  ]);

  const [respData, Loader, refetchConfig] = useAxiosComponentLoader(
    {
      url: CUSTOM_CONFIG_URI,
    },
    configFilter
  );

  const refetchAll = () => {
    refetchConfig();
    retrieveAnalyzersConfiguration();
    retrieveConnectorsConfiguration();
  };

  return (
    <Loader
      render={() => (
        <Formik initialValues={{ config: respData }} onSubmit={null}>
          {({ values: configurations, setFieldValue }) => (
            <Form>
              <FieldArray name="config">
                {({ remove, push }) => (
                  <FormGroup row>
                    <Col>
                      {configurations.config && configurations.config.length > 0
                        ? configurations.config.map((configuration, index) => {
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
                                plugins[configuration.plugin_name].params
                              );
                            if (
                              attributeList.length > 0 &&
                              configuration.attribute &&
                              plugins[configuration.plugin_name].params[
                                configuration.attribute
                              ]
                            ) {
                              const { type } =
                                plugins[configuration.plugin_name].params[
                                  configuration.attribute
                                ];
                              if (type === "str") placeholder = '"string"';
                              else if (type === "int") placeholder = "1234";
                              else if (type === "float") placeholder = "12.34";
                              else if (type === "bool") placeholder = "true";
                              else if (type === "json")
                                placeholder = '{"key": "value"}';
                              else if (type === "list") placeholder = "[...]";
                              else if (type === "dict") placeholder = "{...}";
                            }
                            const disabledSuffix = configuration.edit
                              ? " input-dark "
                              : " disabled text-dark input-secondary ";

                            return (
                              <Row className="py-2" key={`config.${index + 0}`}>
                                <Col>
                                  <Field
                                    as="select"
                                    className={`form-select ${disabledSuffix}`}
                                    disabled={!configuration.edit}
                                    name={`config[${index}].type`}
                                  >
                                    <option value="">---Select Type---</option>
                                    <option value="1">Analyzer</option>
                                    <option value="2">Connector</option>
                                  </Field>
                                </Col>

                                <Col>
                                  <Field
                                    as="select"
                                    className={`form-select ${disabledSuffix}`}
                                    disabled={!configuration.edit}
                                    name={`config[${index}].plugin_name`}
                                  >
                                    <option value="">---Select Name---</option>
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
                                </Col>

                                <Col>
                                  <Field
                                    as="select"
                                    className={`form-select ${disabledSuffix}`}
                                    disabled={!configuration.edit}
                                    name={`config[${index}].attribute`}
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
                                    name={`config.${index}.value`}
                                    className={disabledSuffix}
                                    disabled={!configuration.edit}
                                    placeholder={placeholder}
                                  />
                                </Col>
                                <Button
                                  color="primary"
                                  className="mx-2 rounded-1 text-larger col-auto"
                                  onClick={() => {
                                    if (configuration.edit) {
                                      if (!isValidConfig(configuration)) return;

                                      if (configuration.create)
                                        createCustomConfig({
                                          ...configuration,
                                          ...additionalConfigData,
                                        }).then(() => {
                                          setFieldValue(
                                            `config.${index}.edit`,
                                            false
                                          );
                                          setFieldValue(
                                            `config.${index}.create`,
                                            false
                                          );
                                          refetchAll();
                                        });
                                      else
                                        updateCustomConfig(
                                          configuration,
                                          configuration.id
                                        ).then(() => {
                                          setFieldValue(
                                            `config.${index}.edit`,
                                            false
                                          );
                                          refetchAll();
                                        });
                                    } else
                                      setFieldValue(
                                        `config.${index}.edit`,
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
                                {configuration.edit && !configuration.create ? (
                                  <Button
                                    color="primary"
                                    className="mx-2 rounded-1 text-larger col-auto"
                                    onClick={refetchAll}
                                  >
                                    <MdCancel />
                                  </Button>
                                ) : null}
                                <Button
                                  color="primary"
                                  className="mx-2 rounded-1 text-larger col-auto"
                                  onClick={() => {
                                    if (configuration.create) remove(index);
                                    else
                                      deleteCustomConfig(configuration.id).then(
                                        () => {
                                          remove(index);
                                          refetchAll();
                                        }
                                      );
                                  }}
                                >
                                  <BsFillTrashFill />
                                </Button>
                              </Row>
                            );
                          })
                        : null}
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
                          <BsFillPlusCircleFill /> Add new config
                        </Button>
                      </Row>
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

Config.propTypes = {
  additionalConfigData: PropTypes.object,
  configFilter: PropTypes.func.isRequired,
};

Config.defaultProps = {
  additionalConfigData: {},
};

export default function UserConfig() {
  console.debug("Config rendered!");

  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      <h4>Your custom configuration</h4>
      <Config
        configFilter={(resp) => resp.filter((item) => !item.organization)}
      />
    </Container>
  );
}
