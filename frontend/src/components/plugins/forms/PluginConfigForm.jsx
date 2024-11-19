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
  UncontrolledTooltip,
} from "reactstrap";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";
import { MdDelete, MdInfoOutline } from "react-icons/md";
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
} from "../../../constants/pluginConst";
import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { useAuthStore } from "../../../stores/useAuthStore";

function CustomInput({ formik, config, configType }) {
  const [user] = useAuthStore((state) => [state.user]);
  const { isUserOwner, isUserAdmin } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        isUserOwner: state.isUserOwner,
        isUserAdmin: state.isUserAdmin,
      }),
      [],
    ),
  );

  // Only owner and admins can update org config
  const disabledInputField =
    configType === PluginConfigTypes.ORG_CONFIG &&
    !(isUserOwner || isUserAdmin(user));

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
};

export function PluginConfigForm({
  pluginName,
  pluginType,
  configType,
  configs,
  refetch,
}) {
  console.debug("PluginConfigForm rendered!");

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
            value: formValueJson,
          };
          // org config
          if (configType === PluginConfigTypes.ORG_CONFIG) {
            if (config.organization) {
              obj.organization = config.organization;
            } else if (config.organization === null && config.default) {
              obj.organization = orgName;
            }
          }
          // determinate which config should be created and which should be updated
          if (config.exist && !config.default) {
            configToUpdate.push(obj);
          } else {
            configToCreate.push(obj);
          }
        }
      });

      let responseUpdated = null;
      let responseCreated = null;
      if (configToUpdate.length > 0) {
        responseUpdated = await editPluginConfig(
          pluginType,
          pluginName,
          configToUpdate,
        );
      }
      if (configToCreate.length > 0) {
        responseCreated = await createPluginConfig(
          pluginType,
          pluginName,
          configToCreate,
        );
      }

      if (responseUpdated?.success && responseCreated?.success) {
        formik.setSubmitting(false);
        refetch();
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
                <Col md={2}>
                  <Label
                    className={`me-2 mb-0 ${
                      config?.required ? "required" : ""
                    }`}
                    for={`pluginConfig_${configType}-${config.attribute}`}
                  >
                    {config.attribute}
                  </Label>
                  {config.is_secret && (
                    <>
                      <MdInfoOutline
                        id={`pluginConfig_${configType}-${config.attribute}-secretinfoicon`}
                        fontSize="20"
                      />
                      <UncontrolledTooltip
                        trigger="hover"
                        target={`pluginConfig_${configType}-${config.attribute}-secretinfoicon`}
                        placement="right"
                        fade={false}
                        innerClassName="p-2 text-start text-nowrap md-fit-content"
                      >
                        If an admin of your organization has set a secret you
                        will not be able to see its value but you will see the
                        placeholder *********. You can change the value by
                        setting your personal secret.
                      </UncontrolledTooltip>
                    </>
                  )}
                </Col>
                <Col>
                  <CustomInput
                    formik={formik}
                    config={config}
                    configType={configType}
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
                    title="Delete plugin config"
                    titlePlacement="top"
                    disabled={
                      config.default ||
                      !config.exist ||
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
          <div>No config available</div>
        )}
        <FormGroup className="d-flex justify-content-end align-items-center mt-3">
          <Button
            id="plugin-config"
            type="submit"
            color="primary"
            size="lg"
            outline
            className="mx-2 mt-2"
            disabled={!formik.isValid || formik.isSubmitting}
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
  refetch: PropTypes.func.isRequired,
};

PluginConfigForm.defaultProps = {
  configs: {},
};
