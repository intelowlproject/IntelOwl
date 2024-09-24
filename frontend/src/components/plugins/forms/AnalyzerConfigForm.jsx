import React from "react";
import {
  FormGroup,
  Label,
  Button,
  Input,
  Modal,
  ModalHeader,
  ModalBody,
  Form,
} from "reactstrap";
import { useFormik, FormikProvider } from "formik";
import PropTypes from "prop-types";

import { editPluginConfig, createPluginConfig } from "../pluginsApi";
import { PluginsTypes } from "../../../constants/pluginConst";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { ObservableClassifications } from "../../../constants/jobConst";
import { URL_REGEX } from "../../../constants/regexConst";
import {
  TLPSelectInput,
  TLPSelectInputLabel,
} from "../../common/form/TLPSelectInput";
import { AuthScheme } from "../../../constants/miscConst";

export function AnalyzerConfigForm({ analyzerConfig, toggle, isOpen }) {
  console.debug("AnalyzerConfigForm rendered!");

  const isEditing = Object.keys(analyzerConfig).length > 0;

  // states
  const [responseError, setResponseError] = React.useState(null);

  // store
  const [retrieveAnalyzersConfiguration] = usePluginConfigurationStore(
    (state) => [state.retrieveAnalyzersConfiguration],
  );

  const formik = useFormik({
    initialValues: {
      name: analyzerConfig?.name || "",
      description: analyzerConfig?.description || "",
      tlp: analyzerConfig?.maximum_tlp || "",
      observable_supported: analyzerConfig?.observable_supported || [],
      url: analyzerConfig?.params?.url?.value || "",
      http_method: analyzerConfig?.params?.http_method?.value || "get",
      auth_scheme: analyzerConfig?.params?.auth_scheme.value || "",
      user_agent: analyzerConfig?.params?.user_agent.value || "",
      param_key: analyzerConfig?.params?.param_key.value || "",
      api_key_name: analyzerConfig?.secrets?.api_key_name.value || "",
    },
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);

      const minLength = 3;
      const errors = {};

      if (!values.name) {
        errors.name = "This field is required.";
      } else if (values.name.length < minLength) {
        errors.name = `This field must be at least ${minLength} characters long`;
      }

      if (!values.description || !values.url) {
        errors.description = "This field is required.";
      }

      if (!URL_REGEX.test(values.url)) {
        errors.url = "This is not a valid url.";
      }

      console.debug("formik validation errors");
      console.debug(errors);
      return errors;
    },
    onSubmit: async () => {
      let response;
      const payloadData = {
        name: formik.values.name,
        description: formik.values.description,
        observable_supported: formik.values.observable_supported,
        maximum_tlp: formik.values.tlp,
      };
      if (!isEditing) {
        payloadData.type = "observable";
        payloadData.python_module =
          "basic_observable_analyzer.BasicObservableAnalyzer";
      }
      // plugin config
      payloadData.plugin_config = [
        {
          type: 1,
          plugin_name: formik.values.name,
          attribute: "http_method",
          value: formik.values.http_method,
          config_type: 1,
        },
        {
          type: 1,
          plugin_name: formik.values.name,
          attribute: "url",
          value: formik.values.url,
          config_type: 1,
        },
      ];
      if (formik.values.auth_scheme) {
        payloadData.plugin_config.push({
          type: 1,
          plugin_name: formik.values.name,
          attribute: "auth_scheme",
          value: formik.values.auth_scheme,
          config_type: 1,
        });
      }
      if (formik.values.user_agent) {
        payloadData.plugin_config.push({
          type: 1,
          plugin_name: formik.values.name,
          attribute: "user_agent",
          value: formik.values.user_agent,
          config_type: 1,
        });
      }
      if (formik.values.api_key_name) {
        payloadData.plugin_config.push({
          type: 1,
          plugin_name: formik.values.name,
          attribute: "api_key_name",
          value: formik.values.api_key_name,
          config_type: 2,
        });
      }
      if (formik.values.certificate) {
        payloadData.plugin_config.push({
          type: 1,
          plugin_name: formik.values.name,
          attribute: "certificate",
          value: formik.values.certificate,
          config_type: 2,
        });
      }
      console.debug("payloadData", payloadData);

      if (isEditing) {
        const analyzerToEdit =
          formik.initialValues.name !== formik.values.name
            ? formik.initialValues.name
            : formik.values.name;
        response = await editPluginConfig(
          PluginsTypes.ANALYZER,
          analyzerToEdit,
          payloadData,
        );
      } else {
        response = await createPluginConfig(PluginsTypes.ANALYZER, payloadData);
      }

      console.debug("response:", response);

      if (response?.success) {
        formik.setSubmitting(false);
        setResponseError(null);
        formik.resetForm();
        toggle(false);
        retrieveAnalyzersConfiguration();
      } else {
        setResponseError(response?.error);
      }
    },
  });

  const title = isEditing ? "Edit analyzer config" : "Create a new analyzer";

  return (
    <Modal
      id="analyzer-config-modal"
      autoFocus
      centered
      zIndex="1050"
      size="lg"
      keyboard={false}
      backdrop="static"
      labelledBy="Analyzer config modal"
      isOpen={isOpen}
      style={{ minWidth: "60%" }}
    >
      <ModalHeader className="mx-2" toggle={() => toggle(false)}>
        <small className="text-info">{title}</small>
      </ModalHeader>
      <ModalBody className="m-2">
        <FormikProvider value={formik}>
          <Form onSubmit={formik.handleSubmit}>
            {formik.touched.name && formik.errors.name && (
              <small className="text-danger">{formik.errors.name}</small>
            )}
            <FormGroup className="d-flex align-items-center">
              <Label
                className="me-2 mb-0"
                for="analyzer-name"
                style={{ minWidth: "15%" }}
              >
                Name:
              </Label>
              <Input
                id="analyzer-name"
                type="text"
                name="name"
                value={formik.values.name}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                valid={!formik.errors.name && formik.touched.name}
                invalid={formik.errors.name && formik.touched.name}
                className="bg-darker border-0"
              />
            </FormGroup>
            {formik.touched.description && formik.errors.description && (
              <small className="text-danger">{formik.errors.description}</small>
            )}
            <FormGroup className="d-flex align-items-start">
              <Label
                className="me-2 mb-0 d-flex"
                for="analyzer-description"
                style={{ minWidth: "15%" }}
              >
                Description:
              </Label>
              <Input
                id="analyzer-description"
                type="textarea"
                name="description"
                value={formik.values.description}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                valid={!formik.errors.description && formik.touched.description}
                invalid={
                  formik.errors.description && formik.touched.description
                }
                className="bg-darker border-0"
                style={{
                  minHeight: "100px",
                  overflowX: "scroll",
                }}
              />
            </FormGroup>
            {formik.touched.observable_supported &&
              formik.errors.observable_supported && (
                <small className="text-danger">
                  {formik.errors.observable_supported}
                </small>
              )}
            <FormGroup>
              <Label className="me-4 mb-0" for="observable_supported">
                Observable supported:
              </Label>
              {Object.values(ObservableClassifications).map((type) => (
                <FormGroup check inline key={`observable_supported__${type}`}>
                  <Input
                    id={`observable_supported__${type}`}
                    type="checkbox"
                    name="observable_supported"
                    value={type}
                    checked={formik.values.observable_supported.includes(type)}
                    onBlur={formik.handleBlur}
                    onChange={formik.handleChange}
                  />
                  <Label check>{type}</Label>
                </FormGroup>
              ))}
            </FormGroup>
            <FormGroup className="d-flex">
              <TLPSelectInputLabel size={2} />
              <TLPSelectInput formik={formik} />
            </FormGroup>
            <hr />
            <h5 className="text-accent">Parameters</h5>
            {formik.touched.url && formik.errors.url && (
              <small className="text-danger">{formik.errors.url}</small>
            )}
            <FormGroup className="d-flex align-items-center">
              <Label
                className="me-2 mb-0"
                for="analyzer-url"
                style={{ minWidth: "15%" }}
              >
                Url:
              </Label>
              <Input
                id="analyzer-url"
                type="text"
                name="url"
                value={formik.values.url}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                valid={!formik.errors.url && formik.touched.url}
                invalid={formik.errors.url && formik.touched.url}
                className="bg-darker border-0"
              />
            </FormGroup>
            <FormGroup>
              <Label
                className="me-4 mb-0"
                for="http_method"
                style={{ minWidth: "14%" }}
              >
                HTTP method:
              </Label>
              {["get", "post"].map((method) => (
                <FormGroup check inline key={`http_method__${method}`}>
                  <Input
                    id={`http_method__${method}`}
                    type="checkbox"
                    name="http_method"
                    value={method}
                    checked={formik.values.http_method.includes(method)}
                    onBlur={formik.handleBlur}
                    onChange={formik.handleChange}
                  />
                  <Label check>{method}</Label>
                </FormGroup>
              ))}
            </FormGroup>
            {formik.touched.auth_scheme && formik.errors.auth_scheme && (
              <small className="text-danger">{formik.errors.auth_scheme}</small>
            )}
            <FormGroup className="d-flex align-items-center">
              <Label
                className="me-2 mb-0"
                for="analyzer-auth_scheme"
                style={{ minWidth: "15%" }}
              >
                Authentication scheme:
              </Label>
              <Input
                for="analyzer-auth_scheme"
                type="select"
                name="auth_scheme"
                value={formik.values.auth_scheme}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                className="bg-darker border-0"
              >
                <option value="">Select...</option>
                {Object.values(AuthScheme).map((type) => (
                  <option>{type}</option>
                ))}
              </Input>
            </FormGroup>
            <hr />
            <h5 className="text-accent">Secrets</h5>
            {formik.touched.api_key_name && formik.errors.api_key_name && (
              <small className="text-danger">
                {formik.errors.api_key_name}
              </small>
            )}
            <FormGroup className="d-flex align-items-center">
              <Label
                className="me-2 mb-0"
                for="analyzer-api_key_name"
                style={{ minWidth: "15%" }}
              >
                Api key:
              </Label>
              <Input
                id="analyzer-api_key_name"
                type="text"
                name="url"
                value={formik.values.api_key_name}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                valid={
                  !formik.errors.api_key_name && formik.touched.api_key_name
                }
                invalid={
                  formik.errors.api_key_name && formik.touched.api_key_name
                }
                className="bg-darker border-0"
              />
            </FormGroup>

            <FormGroup className="d-flex justify-content-end align-items-center mt-3">
              {responseError && formik.submitCount && (
                <small className="text-danger">{responseError}</small>
              )}
              <Button
                id="analyzer-config"
                type="submit"
                color="primary"
                size="lg"
                outline
                className="mx-2 mt-2"
                disabled={
                  !formik.dirty || !formik.isValid || formik.isSubmitting
                }
              >
                Save
              </Button>
            </FormGroup>
          </Form>
        </FormikProvider>
      </ModalBody>
    </Modal>
  );
}

AnalyzerConfigForm.propTypes = {
  analyzerConfig: PropTypes.object,
  toggle: PropTypes.func.isRequired,
  isOpen: PropTypes.bool.isRequired,
};

AnalyzerConfigForm.defaultProps = {
  analyzerConfig: {},
};
