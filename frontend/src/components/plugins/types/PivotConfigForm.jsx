import React from "react";
import {
  FormGroup,
  Label,
  Button,
  Spinner,
  Input,
  Modal,
  ModalHeader,
  ModalBody,
} from "reactstrap";
import { Form, useFormik, FormikProvider } from "formik";
import PropTypes from "prop-types";
import ReactSelect from "react-select";
import { selectStyles } from "@certego/certego-ui";

import { PlaybookMultiSelectDropdownInput } from "../../common/form/pluginsMultiSelectDropdownInput";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { PluginsTypes } from "../../../constants/pluginConst";
import { editPluginConfig, createPluginConfig } from "../pluginsApi";

export function PivotConfigForm({ pivotConfig, toggle, isEditing, isOpen }) {
  console.debug("PivotConfigForm rendered!");

  // states
  const [responseError, setResponseError] = React.useState(null);

  // store
  const [retrievePivotsConfiguration] = usePluginConfigurationStore((state) => [
    state.retrievePivotsConfiguration,
  ]);

  const pythonModuleOptions = [
    {
      value: "any_compare.AnyCompare",
      labelDisplay: "Compare field",
      label: (
        <div className="d-flex justify-content-start align-items-start flex-column">
          <div className="d-flex justify-content-start align-items-baseline flex-column">
            <div>Compare field&nbsp;</div>
            <div className="small text-left text-muted">
              Create a custom Pivot from a specific value extracted from the
              results of the analyzers/connectors. <br />
              Set the parameter field to compare with the dotted path to the
              field you would like to extract the value from.
            </div>
          </div>
        </div>
      ),
    },
    {
      value: "self_analyzable.SelfAnalyzable",
      labelDisplay: "Self Analyzable",
      label: (
        <div className="d-flex justify-content-start align-items-start flex-column">
          <div className="d-flex justify-content-start align-items-baseline flex-column">
            <div>Self Analyzable&nbsp;</div>
            <div className="small text-left text-muted">
              Create a custom Pivot that would analyze again the same
              observable/file.
            </div>
          </div>
        </div>
      ),
    },
  ];

  const formik = useFormik({
    initialValues: {
      name: pivotConfig?.name || "",
      description: pivotConfig?.description || "",
      python_module:
        {
          value: pivotConfig?.python_module,
          label:
            pythonModuleOptions.find(
              (element) => element.value === pivotConfig?.python_module,
            )?.label || pivotConfig?.python_module,
        } || {},
      playbook:
        pivotConfig?.playbooks_choice?.map((playbook) => ({
          value: playbook,
          label: playbook,
        })) || [],
      field_to_compare: pivotConfig?.params?.field_to_compare?.value || "",
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

      if (
        values.python_module.value === "any_compare.AnyCompare" &&
        !values.field_to_compare
      ) {
        errors.field_to_compare = "This field is required.";
      }

      if (values.playbook.length === 0) {
        errors.playbook = "This field is required.";
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
        python_module: formik.values.python_module.value,
        playbooks_choice: [formik.values.playbook[0].value],
      };
      if (formik.values.field_to_compare) {
        payloadData.plugin_config = {
          type: 5,
          plugin_name: formik.values.name,
          attribute: "field_to_compare",
          value: formik.values.field_to_compare,
          config_type: 1,
        };
      }

      if (isEditing) {
        const pivotToEdit =
          formik.initialValues.name !== formik.values.name
            ? formik.initialValues.name
            : formik.values.name;
        response = await editPluginConfig(
          PluginsTypes.PIVOT,
          pivotToEdit,
          payloadData,
        );
      } else {
        response = await createPluginConfig(PluginsTypes.PIVOT, payloadData);
      }

      if (response?.success) {
        formik.setSubmitting(false);
        setResponseError(null);
        formik.resetForm();
        toggle(false);
        retrievePivotsConfiguration();
      } else {
        setResponseError(response?.error);
      }
    },
  });

  console.debug("Pivot Config - formik");
  console.debug(formik);

  /* With the setFieldValue the validation and rerender don't work properly: the last update seems to not trigger the validation
      and leaves the UI with values not valid, for this reason the scan button is disabled, but if the user set focus on the UI the last
      validation trigger and start scan is enabled. To avoid this we use this hook that force the validation when the form values change.
      
      This hook is the reason why we can disable the validation in the setFieldValue method (3rd params).
    */
  React.useEffect(() => {
    formik.validateForm();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formik.values]);

  // reset errors if the user change any field after a failed submission
  React.useEffect(() => {
    if (formik.submitCount && responseError) setResponseError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formik.values]);

  const title = isEditing ? "Edit pivot config" : "Create a new pivot";

  return (
    <Modal
      id="pivot-config-modal"
      autoFocus
      centered
      zIndex="1050"
      size="lg"
      keyboard={false}
      backdrop="static"
      labelledBy="Pivot config modal"
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
              <small className="text-danger">Name: {formik.errors.name}</small>
            )}
            <FormGroup className="d-flex align-items-center">
              <Label
                className="me-2 mb-0"
                for="pivot-name"
                style={{ minWidth: "15%" }}
              >
                Name:
              </Label>
              <Input
                id="pivot-name"
                type="text"
                name="name"
                value={formik.values.name}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                valid={!formik.errors.name && formik.touched.name}
                invalid={formik.touched.name && formik.errors.name}
                className="bg-darker border-0"
              />
            </FormGroup>
            {formik.touched.description && formik.errors.description && (
              <small className="text-danger">
                Description: {formik.errors.description}
              </small>
            )}
            <FormGroup className="d-flex align-items-start">
              <Label
                className="me-2 mb-0"
                for="pivot-description"
                style={{ minWidth: "15%" }}
              >
                Description:
              </Label>
              <Input
                id="pivot-description"
                type="textarea"
                name="description"
                value={formik.values.description}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                valid={!formik.errors.description && formik.touched.description}
                invalid={
                  formik.touched.description && formik.errors.description
                }
                className="bg-darker border-0"
                style={{
                  minHeight: "100px",
                  overflowX: "scroll",
                }}
              />
            </FormGroup>
            <FormGroup row className="d-flex align-items-center">
              <Label className="me-2 mb-0" for="pivot-analyzers">
                Field that will be analyzed:
              </Label>
              <ReactSelect
                isClearable={false}
                options={pythonModuleOptions}
                styles={selectStyles}
                value={formik.values.python_module}
                onChange={(value) =>
                  formik.setFieldValue("python_module", value, false)
                }
              />
            </FormGroup>
            {formik.values.python_module.value === "any_compare.AnyCompare" && (
              <FormGroup className="d-flex align-items-center">
                <Label
                  className="me-2 mb-0"
                  for="pivot-field-to-compare"
                  style={{ minWidth: "15%" }}
                >
                  Field to compare:
                </Label>
                <Input
                  id="pivot-field-to-compare"
                  type="text"
                  name="field_to_compare"
                  value={formik.values.field_to_compare}
                  onBlur={formik.handleBlur}
                  onChange={formik.handleChange}
                  className="bg-darker border-0"
                />
              </FormGroup>
            )}
            <FormGroup row className="d-flex align-items-center">
              <Label className="me-2 mb-0" for="pivot-connectors">
                Playbook to Execute:
              </Label>
              <PlaybookMultiSelectDropdownInput
                formik={formik}
                onChange={(playbook) => {
                  formik.setFieldValue("playbook", [playbook], false);
                }}
              />
            </FormGroup>

            <FormGroup className="d-flex justify-content-end align-items-center mt-3">
              {responseError && formik.submitCount && (
                <small className="text-danger">{responseError}</small>
              )}
              <Button
                id="startScan"
                type="submit"
                /* dirty return True if values are different then default
               we cannot run the validation on mount or we get an infinite loop.
              */
                disabled={
                  !formik.dirty || !formik.isValid || formik.isSubmitting
                }
                color="primary"
                size="lg"
                outline
                className="mx-2 mt-2"
              >
                {formik.isSubmitting && <Spinner size="sm" />}Save
              </Button>
            </FormGroup>
          </Form>
        </FormikProvider>
      </ModalBody>
    </Modal>
  );
}

PivotConfigForm.propTypes = {
  pivotConfig: PropTypes.object.isRequired,
  toggle: PropTypes.func.isRequired,
  isEditing: PropTypes.bool.isRequired,
  isOpen: PropTypes.bool.isRequired,
};
