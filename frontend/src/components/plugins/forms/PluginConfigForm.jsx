import React from "react";
import {
  Input,
  Form,
  FormGroup,
  Label,
  Row,
  Col,
  FormFeedback,
  Button,
} from "reactstrap";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";
import { MdDelete } from "react-icons/md";
import { FaUserSecret } from "react-icons/fa";

import PropTypes from "prop-types";
import { useFormik, FormikProvider, FieldArray } from "formik";

import { CustomJsonInput, IconButton } from "@certego/certego-ui";

import {
  createPluginConfig,
  editPluginConfig,
  deletePluginConfig,
} from "../pluginsApi";
import {
  PluginConfigTypes,
  ParameterTypes,
  PluginsTypes,
} from "../../../constants/pluginConst";
import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";

function CustomInput({ formik, config, configType, disabledInputField }) {
  switch (config.type) {
    case ParameterTypes.INT:
      return (
        <>
          <Input
            id={`pluginConfig_${configType}-${config.attribute}`}
            type="number"
            name={config.attribute}
            value={formik.values[config.attribute] || ""}
            onBlur={formik.handleBlur}
            onChange={formik.handleChange}
            invalid={!Number.isInteger(formik.values[config.attribute])}
            className={
              disabledInputField
                ? "disabled bg-darker border-0 input-secondary"
                : "bg-darker border-0"
            }
            disabled={disabledInputField}
            autoComplete={config.is_secret ? "off" : "on"}
          />
          <FormFeedback>This field must be a number.</FormFeedback>
        </>
      );
    case ParameterTypes.FLOAT:
      return (
        <Input
          id={`pluginConfig_${configType}-${config.attribute}`}
          type="number"
          step="0.1"
          name={config.attribute}
          value={formik.values[config.attribute] || ""}
          onBlur={formik.handleBlur}
          onChange={formik.handleChange}
          className={
            disabledInputField
              ? "disabled bg-darker border-0 input-secondary"
              : "bg-darker border-0"
          }
          disabled={disabledInputField}
          autoComplete={config.is_secret ? "off" : "on"}
        />
      );
    case ParameterTypes.STR:
      return (
        <Input
          id={`pluginConfig_${configType}-${config.attribute}`}
          type="text"
          name={config.attribute}
          value={
            formik.values[config.attribute] === "redacted" && config.is_secret
              ? "***********"
              : formik.values[config.attribute]
          }
          onBlur={formik.handleBlur}
          onChange={formik.handleChange}
          className={
            disabledInputField
              ? "disabled bg-darker border-0 input-secondary"
              : "bg-darker border-0"
          }
          disabled={disabledInputField}
          autoComplete={config.is_secret ? "off" : "on"}
        />
      );
    case ParameterTypes.DICT:
      return (
        <div style={{ maxHeight: "150px" }}>
          <CustomJsonInput
            id={`pluginConfig_${configType}-${config.attribute}`}
            placeholder={formik.values[config.attribute]}
            onChange={(value) => {
              formik.setFieldValue(config.attribute, value.jsObject, false);
            }}
            /* waitAfterKeyPress=1000 is the default value and we cannot change it:
                with this value (or higher) in case the user press "save & close" too fast it doesn't take changes.
                If we decrease it (min allowed 100) we don't have this problems, but it's not possible to edit:
                The library auto refresh and move the cursor too fast to make it editable.
            */
            waitAfterKeyPress={1000}
            height="150px"
            viewOnly={disabledInputField}
            confirmGood={!disabledInputField}
          />
        </div>
      );
    case ParameterTypes.BOOL:
      return ["true", "false"].map((value) => (
        <FormGroup
          check
          inline
          key={`pluginConfig_${configType}-${config.attribute}-${value}`}
        >
          <Input
            id={`pluginConfig_${configType}-${config.attribute}-${value}`}
            type="radio"
            name={config.attribute}
            value={value}
            checked={formik.values[config.attribute].toString() === value}
            onBlur={formik.handleBlur}
            onChange={formik.handleChange}
            disabled={disabledInputField}
          />
          <Label
            check
            for={`pluginConfig_${configType}-${config.attribute}-${value}`}
          >
            {value}
          </Label>
        </FormGroup>
      ));
    case ParameterTypes.LIST:
      return (
        <FieldArray
          name={`${config.attribute}`}
          render={(arrayHelpers) => (
            <FormGroup
              row
              id={`pluginConfig_${configType}-${config.attribute}`}
            >
              <Col sm={10}>
                <div style={{ maxHeight: "27vh", overflowY: "scroll" }}>
                  {formik.values[config.attribute] &&
                  formik.values[config.attribute].length > 0
                    ? formik.values[config.attribute].map((value, index) => (
                        <div
                          className="py-2 d-flex"
                          key={`${configType}__value-${index + 0}`}
                        >
                          <Col sm={11} className="ps-1 pe-3">
                            <Input
                              type="text"
                              id={`${configType}__value-${index}`}
                              name={`${configType}__value-${index}`}
                              className={
                                disabledInputField
                                  ? "disabled bg-darker border-0 input-secondary"
                                  : "input-dark"
                              }
                              onChange={(event) => {
                                const attributevalues =
                                  formik.values[config.attribute];
                                attributevalues[index] = event.target.value;
                                formik.setFieldValue(
                                  config.attribute,
                                  attributevalues,
                                  false,
                                );
                              }}
                              value={value}
                              disabled={disabledInputField}
                              autoComplete={config.is_secret ? "off" : "on"}
                            />
                          </Col>
                          <Button
                            color="primary"
                            id={`${configType}__value-${index}-deletebtn`}
                            className="mx-auto rounded-1 text-larger col-sm-1"
                            onClick={() => arrayHelpers.remove(index)}
                            disabled={disabledInputField}
                          >
                            <BsFillTrashFill />
                          </Button>
                        </div>
                      ))
                    : null}
                </div>
                <Row className="my-2 pt-0">
                  <Button
                    color="primary"
                    size="sm"
                    className="mx-auto rounded-1 mx-auto col-sm-auto d-flex align-items-center"
                    onClick={() => arrayHelpers.push("")}
                    disabled={disabledInputField}
                  >
                    <BsFillPlusCircleFill />
                    &nbsp;Add new value
                  </Button>
                </Row>
              </Col>
            </FormGroup>
          )}
        />
      );
    default:
      return <div>Type not supported</div>;
  }
}

CustomInput.propTypes = {
  formik: PropTypes.object.isRequired,
  config: PropTypes.object.isRequired,
  configType: PropTypes.string.isRequired,
  disabledInputField: PropTypes.bool.isRequired,
};

function calculateStateSelector(pluginType) {
  switch (pluginType) {
    case PluginsTypes.ANALYZER:
      return (state) => [state.retrieveAnalyzersConfiguration];
    case PluginsTypes.CONNECTOR:
      return (state) => [state.retrieveConnectorsConfiguration];
    case PluginsTypes.VISUALIZER:
      return (state) => [state.retrieveVisualizersConfiguration];
    case PluginsTypes.PIVOT:
      return (state) => [state.retrievePivotsConfiguration];
    case PluginsTypes.INGESTOR:
      return (state) => [state.retrieveIngestorsConfiguration];
    default:
      return [];
  }
}

export function PluginConfigForm({
  pluginName,
  pluginType,
  configType,
  configs,
  isUserOwnerOrAdmin,
  refetch,
  toggle,
}) {
  console.debug("PluginConfigForm rendered!");

  // API/ store
  const [retrievePlugins] = usePluginConfigurationStore(
    calculateStateSelector(pluginType),
  );

  const {
    organization: { name: orgName },
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        organization: state.organization,
      }),
      [],
    ),
  );

  // Only owner and admins can create/update/delete org config
  const disabledOrgActions =
    configType === PluginConfigTypes.ORG_CONFIG && !isUserOwnerOrAdmin;

  const initialValues = {};
  configs.forEach((config) => {
    if (config.type === ParameterTypes.DICT) {
      initialValues[config.attribute] = JSON.parse(config.value) || {};
    } else if (config.type === ParameterTypes.LIST) {
      initialValues[config.attribute] = JSON.parse(config.value) || [];
    } else if (config.type === ParameterTypes.STR) {
      initialValues[config.attribute] = config.value || "";
    } else if (config.type === ParameterTypes.INT) {
      initialValues[config.attribute] = JSON.parse(config.value);
    } else {
      initialValues[config.attribute] = config.value;
    }
  });
  console.debug("initialValues", initialValues);

  const formik = useFormik({
    initialValues,
    onSubmit: async () => {
      const configToCreate = [];
      const configToUpdate = [];

      configs.forEach((config) => {
        const formValueJson = JSON.stringify(formik.values[config.attribute]);
        const initialValuesJson = JSON.stringify(
          initialValues[config.attribute],
        );
        if (formValueJson !== initialValuesJson) {
          const obj = {
            attribute: config.attribute,
            value:
              config.type === ParameterTypes.BOOL
                ? formik.values[config.attribute]
                : formValueJson,
          };

          // determinate which config should be created and which should be updated
          // CREATE
          if (
            !config.exist || // no config
            (config.exist && config.owner === null) || // defualt config
            (configType === PluginConfigTypes.USER_CONFIG &&
              config.exist &&
              config.for_organization) // org override
          ) {
            if (configType === PluginConfigTypes.ORG_CONFIG) {
              obj.organization = config.organization || orgName;
            } else {
              obj.for_organization = false;
            }
            const pluginSlugName = `${pluginType}_config`;
            obj[pluginSlugName] = pluginName;
            obj.parameter = config.parameter;
            configToCreate.push(obj);
          } else {
            // UPDATE
            obj.id = config.id;
            configToUpdate.push(obj);
          }
        }
      });

      let responseCreated = { success: true, error: null };
      let responseUpdated = { success: true, error: null };
      if (configToCreate.length > 0) {
        responseCreated = await createPluginConfig(
          pluginType,
          pluginName,
          configToCreate,
        );
      }
      if (configToUpdate.length > 0) {
        responseUpdated = await editPluginConfig(
          pluginType,
          pluginName,
          configToUpdate,
        );
      }

      if (responseUpdated.success && responseCreated.success) {
        formik.setSubmitting(false);
        formik.resetForm();
        toggle(false);
        retrievePlugins();
      }
      return null;
    },
  });

  const onDelete = async (configId) => {
    try {
      await deletePluginConfig(configId);
      refetch();
    } catch {
      // handle error in deletePluginConfig
    }
  };

  return (
    <FormikProvider value={formik}>
      <Form onSubmit={formik.handleSubmit}>
        <hr />
        {configs.length ? (
          configs.map((config) => (
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label
                    className={`me-2 mb-0 ${
                      config?.required ? "required" : ""
                    }`}
                    for={`pluginConfig_${configType}-${config.attribute}`}
                  >
                    {config.attribute}
                  </Label>
                  {config.is_secret && <FaUserSecret />}
                </Col>
                <Col>
                  <CustomInput
                    formik={formik}
                    config={config}
                    configType={configType}
                    disabledInputField={disabledOrgActions}
                  />
                </Col>
                <Col md={1}>
                  <IconButton
                    id={`pluginConfig_${configType}-${config.attribute}-deletebtn`}
                    Icon={MdDelete}
                    size="sm"
                    color="info"
                    className="text-white me-2"
                    onClick={() => onDelete(config.id)}
                    title="Delete custom config - If a default exists it will be restored"
                    titlePlacement="top"
                    disabled={
                      !config.exist ||
                      config.owner === null ||
                      disabledOrgActions ||
                      (config.organization !== null &&
                        configType === PluginConfigTypes.USER_CONFIG)
                    }
                  />
                </Col>
              </Row>
              <Row>
                <Col className="offset-2 col-9">
                  <small className="mt-1 fst-italic">
                    {config.description}
                  </small>
                </Col>
              </Row>
              <hr />
            </FormGroup>
          ))
        ) : (
          <div className="text-muted fst-italic">No parameters available</div>
        )}
        <FormGroup className="d-flex justify-content-end align-items-center mt-3">
          <Button
            id="plugin-config"
            type="submit"
            color="primary"
            size="lg"
            outline
            className="mx-2 mt-2"
            /* dirty return True if values are different then default
              we cannot run the validation on mount or we get an infinite loop.
            */
            disabled={!formik.isValid || formik.isSubmitting || !formik.dirty}
          >
            Save
          </Button>
        </FormGroup>
      </Form>
    </FormikProvider>
  );
}

PluginConfigForm.propTypes = {
  pluginName: PropTypes.string.isRequired,
  pluginType: PropTypes.oneOf(["analyzer", "connector", "ingestor", "pivot"])
    .isRequired,
  configType: PropTypes.oneOf(Object.values(PluginConfigTypes)).isRequired,
  configs: PropTypes.arrayOf(Object),
  isUserOwnerOrAdmin: PropTypes.bool.isRequired,
  refetch: PropTypes.func.isRequired,
  toggle: PropTypes.func.isRequired,
};

PluginConfigForm.defaultProps = {
  configs: {},
};
