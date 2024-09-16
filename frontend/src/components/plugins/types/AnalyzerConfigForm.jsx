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
import PropTypes from "prop-types";

export function AnalyzerConfigForm({ config, toggle, isEditing, isOpen }) {
  console.debug("AnalyzerConfigForm rendered!");

  // states
  const [formErrors, setFormErrors] = React.useState({});

  const initialValues = {
    name: config?.name || "",
    description: config?.description || "",
  };
  console.debug("initialValues", initialValues);

  const [formValues, setFormValues] = React.useState(initialValues);
  console.debug("formValues", formValues);

  const isValidForm = (values) => {
    console.debug("validate - values");
    console.debug(values);

    const minLength = 3;
    const errors = {};

    if (!values.name) {
      errors.name = "This field is required.";
    } else if (values.name.length < minLength) {
      errors.name = `This field must be at least ${minLength} characters long`;
    }

    console.debug("Validation errors");
    console.debug(errors);
    setFormErrors(errors);

    if (Object.keys(errors).length) return false;
    return true;
  };

  const onSubmit = async () => {
    let response;

    const payloadData = {
      name: formValues.name,
      python_module: formValues.python_module.value,
      playbooks_choice: [formValues.playbook[0].value],
      related_analyzer_configs: formValues.analyzers.map(
        (analyzer) => analyzer.value,
      ),
      related_connector_configs: formValues.connectors.map(
        (connector) => connector.value,
      ),
    };
    if (formValues.field_to_compare) {
      payloadData.plugin_config = {
        type: 5,
        plugin_name: formValues.name,
        attribute: "field_to_compare",
        value: formValues.field_to_compare,
        config_type: 1,
      };
    }

    if (isEditing) {
      const analyzerToEdit =
        initialValues.name !== formValues.name
          ? initialValues.name
          : formValues.name;
      console.debug("analyzerToEdit:", analyzerToEdit);
      // response = await editPluginConfig(
      //   PluginsTypes.PIVOT,
      //   pivotToEdit,
      //   payloadData,
      // );
    } else {
      console.debug("analyzerToCreate:", formValues.name);
      // response = await createPluginConfig(PluginsTypes.PIVOT, payloadData);
    }

    console.debug("response:", response);

    // if (response?.success) {
    //   formik.setSubmitting(false);
    //   setResponseError(null);
    //   formik.resetForm();
    //   toggle(false);
    //   retrievePivotsConfiguration();
    // } else {
    //   setResponseError(response?.error);
    // }
  };

  const title = isEditing ? "Edit analyzer config" : "Create a new analyzer";

  console.debug("formErrors", formErrors);

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
        <Form onSubmit={onSubmit}>
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
              value={formValues.name}
              onChange={(event) => {
                if (isValidForm({ ...formValues, name: event.target.value })) {
                  setFormValues({
                    ...formValues,
                    name: event.target.value,
                  });
                }
              }}
              className="bg-darker border-0"
            />
          </FormGroup>
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
              value={formValues.description}
              onChange={(event) => {
                if (
                  isValidForm({
                    ...formValues,
                    description: event.target.value,
                  })
                ) {
                  setFormValues({
                    ...formValues,
                    description: event.target.value,
                  });
                }
              }}
              className="bg-darker border-0"
              style={{
                minHeight: "100px",
                overflowX: "scroll",
              }}
            />
          </FormGroup>

          <FormGroup className="d-flex justify-content-end align-items-center mt-3">
            <Button
              id="analyzer-config"
              type="submit"
              color="primary"
              size="lg"
              outline
              className="mx-2 mt-2"
            >
              Save
            </Button>
          </FormGroup>
        </Form>
      </ModalBody>
    </Modal>
  );
}

AnalyzerConfigForm.propTypes = {
  config: PropTypes.object.isRequired,
  toggle: PropTypes.func.isRequired,
  isEditing: PropTypes.bool.isRequired,
  isOpen: PropTypes.bool.isRequired,
};
