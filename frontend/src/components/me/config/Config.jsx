import { addToast, useAxiosComponentLoader } from "@certego/certego-ui";
import { Field, FieldArray, Form, Formik } from "formik";
import React from "react";
import { MdCancel } from "react-icons/md";
import {
  BsFillCheckSquareFill,
  BsFillPencilFill,
  BsFillPlusCircleFill,
  BsFillTrashFill,
} from "react-icons/bs";
import { Button, Col, Container, FormGroup, Input, Row } from "reactstrap";
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
  const objectFilter = (obj, predicate) =>
    Object.keys(obj)
      .filter((key) => predicate(obj[key]))
      .reduce((res, key) => Object.assign(res, { [key]: obj[key] }), {});
  return objectFilter(
    plugins,
    (item) => item.params && Object.keys(item.params).length > 0
  );
}

export default function Config() {
  console.debug("Config rendered!");

  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

  const [analyzers, connectors] = usePluginConfigurationStore((state) => [
    filterEmptyParams(state.analyzersJSON),
    filterEmptyParams(state.connectorsJSON),
  ]);

  const [respData, Loader, refetch] = useAxiosComponentLoader(
    {
      url: CUSTOM_CONFIG_URI,
    },
    (resp) => resp.filter((item) => !item.organization)
  );

  return (
    <Container>
      <h4>Your custom configuration</h4>
      <Loader
        render={() => (
          <Formik initialValues={{ config: respData }} onSubmit={null}>
            {({ values, setFieldValue }) => (
              <Form>
                <FieldArray name="config">
                  {({ remove, push }) => (
                    <FormGroup row>
                      <Col>
                        {values.config && values.config.length > 0
                          ? values.config.map((item, index) => {
                              let plugins;
                              let attributeList = [];
                              if (item.type === "1") {
                                plugins = analyzers;
                              } else if (item.type === "2") {
                                plugins = connectors;
                              } else {
                                plugins = {};
                              }
                              if (item.plugin_name && plugins[item.plugin_name])
                                attributeList = Object.keys(
                                  plugins[item.plugin_name].params
                                );
                              const disabledSuffix = item.edit
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
                                      disabled={!item.edit}
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
                                      disabled={!item.edit}
                                      name={`config[${index}].plugin_name`}
                                    >
                                      <option value="">
                                        ---Select Name---
                                      </option>
                                      {Object.values(plugins).map((plugin) => (
                                        <option
                                          value={plugin.name}
                                          key={plugin.name}
                                        >
                                          {plugin.name}
                                        </option>
                                      ))}
                                    </Field>
                                  </Col>

                                  <Col>
                                    <Field
                                      as="select"
                                      className={`form-select ${disabledSuffix}`}
                                      disabled={!item.edit}
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
                                      disabled={!item.edit}
                                    />
                                  </Col>
                                  <Button
                                    color="primary"
                                    className="mx-2 rounded-1 text-larger col-auto"
                                    onClick={() => {
                                      if (item.edit) {
                                        if (!isValidConfig(item)) return;

                                        if (item.create)
                                          createCustomConfig(item).then(() => {
                                            setFieldValue(
                                              `config.${index}.edit`,
                                              false
                                            );
                                            setFieldValue(
                                              `config.${index}.create`,
                                              false
                                            );
                                            refetch();
                                          });
                                        else
                                          updateCustomConfig(
                                            item,
                                            item.id
                                          ).then(() => {
                                            setFieldValue(
                                              `config.${index}.edit`,
                                              false
                                            );
                                          });
                                      } else
                                        setFieldValue(
                                          `config.${index}.edit`,
                                          true
                                        );
                                    }}
                                  >
                                    {item.edit ? (
                                      <BsFillCheckSquareFill />
                                    ) : (
                                      <BsFillPencilFill />
                                    )}
                                  </Button>
                                  {item.edit && !item.create ? (
                                    <Button
                                      color="primary"
                                      className="mx-2 rounded-1 text-larger col-auto"
                                      onClick={refetch}
                                    >
                                      <MdCancel />
                                    </Button>
                                  ) : null}
                                  <Button
                                    color="primary"
                                    className="mx-2 rounded-1 text-larger col-auto"
                                    onClick={() => {
                                      if (item.create) remove(index);
                                      else
                                        deleteCustomConfig(item.id).then(() =>
                                          remove(index)
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
