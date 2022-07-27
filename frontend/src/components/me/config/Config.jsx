import { addToast, useAxiosComponentLoader } from "@certego/certego-ui";
import { Field, FieldArray, Form, Formik } from "formik";
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
      (key) =>
        plugins[key].params && Object.keys(plugins[key].params).length > 0
    )
    .reduce((res, key) => Object.assign(res, { [key]: plugins[key] }), {});
}

export default function Config() {
  console.debug("Config rendered!");

  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

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
    (resp) => resp.filter((item) => !item.organization)
  );

  const refetchAll = () => {
    refetchConfig();
    retrieveAnalyzersConfiguration();
    retrieveConnectorsConfiguration();
  };

  return (
    <Container>
      <h4>Your custom configuration</h4>
      <Loader
        render={() => (
          <Formik initialValues={{ config: respData }} onSubmit={null}>
            {({ values: configurations, setFieldValue }) => (
              <Form>
                <FieldArray name="config">
                  {({ remove, push }) => (
                    <FormGroup row>
                      <Col>
                        {configurations.config &&
                        configurations.config.length > 0
                          ? configurations.config.map((plugin, index) => {
                              let plugins;
                              let attributeList = [];
                              let placeholder = "";
                              if (plugin.type === "1") {
                                plugins = analyzers;
                              } else if (plugin.type === "2") {
                                plugins = connectors;
                              } else {
                                plugins = {};
                              }
                              if (
                                plugin.plugin_name &&
                                plugins[plugin.plugin_name]
                              )
                                attributeList = Object.keys(
                                  plugins[plugin.plugin_name].params
                                );
                              if (
                                attributeList.length > 0 &&
                                plugin.attribute &&
                                plugins[plugin.plugin_name].params[
                                  plugin.attribute
                                ]
                              ) {
                                const { type } =
                                  plugins[plugin.plugin_name].params[
                                    plugin.attribute
                                  ];
                                if (type === "str") placeholder = '"string"';
                                else if (type === "int") placeholder = "1234";
                                else if (type === "float")
                                  placeholder = "12.34";
                                else if (type === "bool") placeholder = "true";
                                else if (type === "json")
                                  placeholder = '{"key": "value"}';
                                else if (type === "list") placeholder = "[]";
                              }
                              const disabledSuffix = plugin.edit
                                ? " input-dark "
                                : " disabled text-dark input-secondary ";

                              return (
                                <Row
                                  className="py-2"
                                  key={`config.${index + 0}`}
                                >
                                  <Col>
                                    <Field
                                      as="select"
                                      className={`form-select ${disabledSuffix}`}
                                      disabled={!plugin.edit}
                                      name={`config[${index}].type`}
                                    >
                                      <option value="">
                                        ---Select Type---
                                      </option>
                                      <option value="1">Analyzer</option>
                                      <option value="2">Connector</option>
                                    </Field>
                                  </Col>

                                  <Col>
                                    <Field
                                      as="select"
                                      className={`form-select ${disabledSuffix}`}
                                      disabled={!plugin.edit}
                                      name={`config[${index}].plugin_name`}
                                    >
                                      <option value="">
                                        ---Select Name---
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
                                  </Col>

                                  <Col>
                                    <Field
                                      as="select"
                                      className={`form-select ${disabledSuffix}`}
                                      disabled={!plugin.edit}
                                      name={`config[${index}].attribute`}
                                    >
                                      <option value="">
                                        ---Select Attribute---
                                      </option>
                                      {attributeList.map((attribute) => (
                                        <option
                                          value={attribute}
                                          key={attribute}
                                        >
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
                                      disabled={!plugin.edit}
                                      placeholder={placeholder}
                                    />
                                  </Col>
                                  <Button
                                    color="primary"
                                    className="mx-2 rounded-1 text-larger col-auto"
                                    onClick={() => {
                                      if (plugin.edit) {
                                        if (!isValidConfig(plugin)) return;

                                        if (plugin.create)
                                          createCustomConfig(plugin).then(
                                            () => {
                                              setFieldValue(
                                                `config.${index}.edit`,
                                                false
                                              );
                                              setFieldValue(
                                                `config.${index}.create`,
                                                false
                                              );
                                              refetchAll();
                                            }
                                          );
                                        else
                                          updateCustomConfig(
                                            plugin,
                                            plugin.id
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
                                    {plugin.edit ? (
                                      <BsFillCheckSquareFill />
                                    ) : (
                                      <BsFillPencilFill />
                                    )}
                                  </Button>
                                  {plugin.edit && !plugin.create ? (
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
                                      if (plugin.create) remove(index);
                                      else
                                        deleteCustomConfig(plugin.id).then(
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
    </Container>
  );
}
