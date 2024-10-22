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
  Row,
  Col,
} from "reactstrap";
import { Link } from "react-router-dom";
import { useFormik, FormikProvider } from "formik";
import PropTypes from "prop-types";
import { CustomJsonInput } from "@certego/certego-ui";

import { editPluginConfig, createPluginConfig } from "../pluginsApi";
import { PluginsTypes } from "../../../constants/pluginConst";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { ObservableClassifications } from "../../../constants/jobConst";
import { URL_REGEX } from "../../../constants/regexConst";
import {
  TLPSelectInput,
  TLPSelectInputLabel,
} from "../../common/form/TLPSelectInput";
import { HTTPMethods } from "../../../constants/miscConst";

export function AnalyzerConfigForm({ analyzerConfig, toggle, isOpen }) {
  console.debug("AnalyzerConfigForm rendered!");

  const isEditing = Object.keys(analyzerConfig).length > 0;

  // states
  const [responseError, setResponseError] = React.useState(null);
  const [headersJsonInput, setHeadersJsonInput] = React.useState({});
  const [paramsJsonInput, setParamsJsonInput] = React.useState({});

  // store
  const [retrieveAnalyzersConfiguration] = usePluginConfigurationStore(
    (state) => [state.retrieveAnalyzersConfiguration],
  );

  const formik = useFormik({
    initialValues: {
      name: analyzerConfig?.name || "",
      description: analyzerConfig?.description || "",
      observable_supported: analyzerConfig?.observable_supported || [],
      tlp: analyzerConfig?.maximum_tlp || "RED",
      url: analyzerConfig?.params?.url?.value || "",
      http_method: analyzerConfig?.params?.http_method?.value || "get",
      headers: analyzerConfig?.params?.headers?.value || {
        Accept: "application/json",
      },
      params: analyzerConfig?.params?.params?.value || {
        param_name: "<observable>",
      },
      api_key_name: analyzerConfig?.secrets?.api_key_name?.value || "",
      certificate: analyzerConfig?.secrets?.certificate?.value || "",
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

      if (!/^[a-zA-Z0-9_]+$/.test(values.name)) {
        errors.name =
          "This is not a valid name. It only supports alphanumeric characters and underscore";
      }

      if (!values.description) {
        errors.description = "This field is required.";
      } else if (values.description.length < minLength) {
        errors.description = `This field must be at least ${minLength} characters long`;
      }

      if (values.observable_supported.length === 0) {
        errors.observable_supported = "This field is required.";
      }

      if (!values.url) {
        errors.url = "This field is required.";
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
        {
          type: 1,
          plugin_name: formik.values.name,
          attribute: "headers",
          value:
            headersJsonInput?.json || JSON.stringify(formik.values.headers),
          config_type: 1,
        },
        {
          type: 1,
          plugin_name: formik.values.name,
          attribute: "api_key_name",
          value: JSON.stringify(formik.values.api_key_name),
          config_type: 2,
        },
        {
          type: 1,
          plugin_name: formik.values.name,
          attribute: "certificate",
          value: JSON.stringify(formik.values.certificate),
          config_type: 2,
        },
        {
          type: 1,
          plugin_name: formik.values.name,
          attribute: "params",
          value: paramsJsonInput?.json || JSON.stringify({}),
          config_type: 1,
        },
      ];

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
            <FormGroup>
              <Row>
                <Col md={2}>
                  <Label className="me-2 mb-0 required" for="analyzer-name">
                    Name:
                  </Label>
                </Col>
                <Col>
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
                  {formik.touched.name && formik.errors.name && (
                    <small className="text-danger">{formik.errors.name}</small>
                  )}
                </Col>
              </Row>
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2}>
                  <Label
                    className="me-2 mb-0 required"
                    for="analyzer-description"
                  >
                    Description:
                  </Label>
                </Col>
                <Col>
                  <Input
                    id="analyzer-description"
                    type="textarea"
                    name="description"
                    value={formik.values.description}
                    onBlur={formik.handleBlur}
                    onChange={formik.handleChange}
                    valid={
                      !formik.errors.description && formik.touched.description
                    }
                    invalid={
                      formik.errors.description && formik.touched.description
                    }
                    className="bg-darker border-0"
                    style={{
                      minHeight: "100px",
                      overflowX: "scroll",
                    }}
                  />
                  {formik.touched.description && formik.errors.description && (
                    <small className="text-danger">
                      {formik.errors.description}
                    </small>
                  )}
                </Col>
              </Row>
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2}>
                  <Label
                    className="me-2 mb-0 required"
                    for="observable_supported"
                  >
                    Observable supported:
                  </Label>
                </Col>
                <Col className="d-flex align-items-center">
                  {Object.values(ObservableClassifications).map((type) => (
                    <FormGroup
                      check
                      inline
                      key={`observable_supported__${type}`}
                    >
                      <Input
                        id={`observable_supported__${type}`}
                        type="checkbox"
                        name="observable_supported"
                        value={type}
                        checked={formik.values.observable_supported.includes(
                          type,
                        )}
                        onBlur={formik.handleBlur}
                        onChange={formik.handleChange}
                      />
                      <Label check>{type}</Label>
                    </FormGroup>
                  ))}
                  {formik.touched.observable_supported &&
                    formik.errors.observable_supported && (
                      <small className="text-danger">
                        {formik.errors.observable_supported}
                      </small>
                    )}
                </Col>
              </Row>
            </FormGroup>
            <FormGroup className="d-flex">
              <TLPSelectInputLabel size={2} />
              <TLPSelectInput formik={formik} />
            </FormGroup>
            <h5 className={isEditing ? "mb-0" : ""}>
              <small className="text-info">Plugin Config</small>
            </h5>
            {isEditing && (
              <small className="text-muted">
                Note: Your plugin configuration overrides your{" "}
                <Link to="/me/organization/config">
                  organization&apos;s configuration
                </Link>{" "}
                (if any).
              </small>
            )}
            <hr className="mt-0" />
            <FormGroup>
              <Row>
                <Col md={2}>
                  <Label className="me-2 mb-0 required" for="analyzer-url">
                    Url:
                  </Label>
                </Col>
                <Col>
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
                    placeholder="ex: http://www.service.com/"
                  />
                  <div className="d-flex flex-column mt-1">
                    <small className="mt-0 fst-italic">
                      URL of the instance you want to connect to
                    </small>
                    {formik.touched.url && formik.errors.url && (
                      <small className="text-danger">{formik.errors.url}</small>
                    )}
                  </div>
                </Col>
              </Row>
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2}>
                  <Label className="me-2 mb-0 required" for="http_method">
                    HTTP method:
                  </Label>
                </Col>
                <Col>
                  {Object.values(HTTPMethods).map((method) => (
                    <FormGroup check inline key={`http_method__${method}`}>
                      <Input
                        id={`http_method__${method}`}
                        type="radio"
                        name="http_method"
                        value={method}
                        checked={formik.values.http_method.includes(method)}
                        onBlur={formik.handleBlur}
                        onChange={formik.handleChange}
                      />
                      <Label check for={`http_method__${method}`}>
                        {method.toUpperCase()}
                      </Label>
                    </FormGroup>
                  ))}
                </Col>
              </Row>
              {formik.values.http_method === HTTPMethods.GET ? (
                <Row className="mt-2">
                  <Col md={10} className="offset-2">
                    <small className="fst-italic">
                      <strong>Request formats</strong>
                      <ul>
                        <li>
                          Query string (default):&nbsp;
                          <strong className="text-primary fst-italic">
                            http://www.service.com?param_name=&lt;observable&gt;
                          </strong>
                          . The section below must be filled in correctly.&nbsp;
                        </li>
                        <li>
                          REST:&nbsp;
                          <strong className="text-primary fst-italic">
                            http://www.service.com/&lt;observable&gt;
                          </strong>
                          . The params section below must be empty. In that case
                          the analyzed observable will be automatically added to
                          the URL during the analysis.
                        </li>
                      </ul>
                    </small>
                  </Col>
                </Row>
              ) : (
                <Row className="mt-2">
                  <Col md={10} className="offset-2">
                    <div className="d-flex">
                      <small className="fst-italic">
                        The entire dictionary in the section below will be used
                        as the payload for the request.
                      </small>
                    </div>
                  </Col>
                </Row>
              )}
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2}>
                  <Label
                    className={`me-2 mb-0 ${
                      formik.values.http_method === HTTPMethods.GET
                        ? ""
                        : "required"
                    }`}
                    for="analyzer_json_param"
                  >
                    Params/Payload:
                  </Label>
                </Col>
                <Col md={10}>
                  <div style={{ maxHeight: "150px" }}>
                    <CustomJsonInput
                      id="analyzer_json_param"
                      placeholder={formik.values.params}
                      onChange={setParamsJsonInput}
                      /* waitAfterKeyPress=1000 is the default value and we cannot change it:
                          with this value (or higher) in case the user press "save & close" too fast it doesn't take changes.
                          If we decrease it (min allowed 100) we don't have this problems, but it's not possible to edit:
                          The library auto refresh and move the cursor too fast to make it editable.
                        */
                      waitAfterKeyPress={1000}
                      height="150px"
                    />
                  </div>
                  <div className="d-flex flex-column mt-1">
                    <small className="mt-0 fst-italic">
                      You have to change &lt;param_name&gt; key to the correct
                      name. It is possible to add other parameters.
                      <br />
                      Note: the &lt;observable&gt; placeholder will be
                      automatically replaced during the analysis.
                    </small>
                  </div>
                </Col>
              </Row>
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2} sm={12}>
                  <Label className="me-2 mb-0" for="analyzer_header">
                    Headers:
                  </Label>
                </Col>
                <Col md={10}>
                  <div style={{ maxHeight: "150px" }}>
                    <CustomJsonInput
                      id="analyzer_header"
                      placeholder={formik.values.headers}
                      onChange={setHeadersJsonInput}
                      /* waitAfterKeyPress=1000 is the default value and we cannot change it:
                          with this value (or higher) in case the user press "save & close" too fast it doesn't take changes.
                          If we decrease it (min allowed 100) we don't have this problems, but it's not possible to edit:
                          The library auto refresh and move the cursor too fast to make it editable.
                        */
                      waitAfterKeyPress={1000}
                      height="150px"
                    />
                  </div>
                  <div className="d-flex flex-column mt-1">
                    <small className="mt-0 fst-italic">
                      Headers used for the request. <br />
                      If <strong>Authorization</strong> is required, you must
                      use the &lt;api_key&gt; placeholder insead of actual API
                      key. ex: Authorization: &apos;Token &lt;api_key&gt;&apos;
                    </small>
                  </div>
                </Col>
              </Row>
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2}>
                  <Label className="me-2 mb-0" for="analyzer-api_key_name">
                    Api key:
                  </Label>
                </Col>
                <Col>
                  <Input
                    id="analyzer-api_key_name"
                    type="text"
                    name="api_key_name"
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
                  <div className="d-flex flex-column mt-1">
                    <small className="mt-0 fst-italic">
                      API key required for authentication. It will replace the
                      &lt;api_key&gt; placeholder in the header.
                    </small>
                    {formik.touched.api_key_name &&
                      formik.errors.api_key_name && (
                        <small className="text-danger">
                          {formik.errors.api_key_name}
                        </small>
                      )}
                  </div>
                </Col>
              </Row>
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2}>
                  <Label className="me-2 mb-0" for="analyzer-certificate">
                    Certificate:
                  </Label>
                </Col>
                <Col>
                  <Input
                    id="analyzer-certificate"
                    type="textarea"
                    name="certificate"
                    value={formik.values.certificate}
                    onBlur={formik.handleBlur}
                    onChange={formik.handleChange}
                    valid={
                      !formik.errors.certificate && formik.touched.certificate
                    }
                    invalid={
                      formik.errors.certificate && formik.touched.certificate
                    }
                    className="bg-darker border-0"
                    style={{
                      minHeight: "150px",
                      overflowX: "scroll",
                    }}
                    placeholder={`-----BEGIN CERTIFICATE-----\n. . .\n-----END CERTIFICATE-----`}
                  />
                  <div className="d-flex flex-column mt-1">
                    <small className="mt-0 fst-italic">
                      Self signed SSL certificate for internal services
                    </small>
                    {formik.touched.certificate &&
                      formik.errors.certificate && (
                        <small className="text-danger">
                          {formik.errors.certificate}
                        </small>
                      )}
                  </div>
                </Col>
              </Row>
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
                  !formik.isValid ||
                  formik.isSubmitting ||
                  headersJsonInput?.error ||
                  paramsJsonInput?.error
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
