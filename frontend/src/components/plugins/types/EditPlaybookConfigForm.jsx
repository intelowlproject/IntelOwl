import React from "react";
import { FormGroup, Label, Button, Spinner, Input } from "reactstrap";
import { Form, useFormik, FormikProvider } from "formik";
import PropTypes from "prop-types";

import {
  AnalyzersMultiSelectDropdownInput,
  ConnectorsMultiSelectDropdownInput,
  VisualizersMultiSelectDropdownInput,
  PivotsMultiSelectDropdownInput,
} from "../../common/form/pluginsMultiSelectDropdownInput";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import {
  TLPSelectInput,
  TLPSelectInputLabel,
} from "../../common/form/TLPSelectInput";
import { AllPluginSupportedTypes } from "../../../constants/pluginConst";
import { ScanConfigSelectInput } from "../../common/form/ScanConfigSelectInput";
import { parseScanCheckTime } from "../../../utils/time";
import { TagSelectInput } from "../../common/form/TagSelectInput";
import { JobTag } from "../../common/JobTag";
import { TlpChoices } from "../../../constants/advancedSettingsConst";
import {
  EditRuntimeConfiguration,
  runtimeConfigurationParam,
  saveRuntimeConfiguration,
} from "../../common/form/runtimeConfigurationInput";

// constants
const stateSelector = (state) => [
  state.analyzers,
  state.connectors,
  state.visualizers,
  state.pivots,
  state.editPlaybookConfig,
];

export function EditPlaybookConfigForm({ playbookConfig, toggle }) {
  console.debug("EditPlaybookConfigForm rendered!");

  const [jsonInput, setJsonInput] = React.useState({});
  const [analyzers, connectors, visualizers, pivots, editPlaybookConfig] =
    usePluginConfigurationStore(stateSelector);

  const [responseError, setResponseError] = React.useState(null);

  const formik = useFormik({
    initialValues: {
      name: playbookConfig.name,
      description: playbookConfig.description,
      type: playbookConfig.type,
      analyzers: playbookConfig.analyzers.map((analyzer) => ({
        value: analyzer,
        label: analyzer,
      })),
      connectors: playbookConfig.connectors.map((connector) => ({
        value: connector,
        label: connector,
      })),
      visualizers: playbookConfig.visualizers.map((visualizer) => ({
        value: visualizer,
        label: visualizer,
      })),
      pivots: playbookConfig.pivots.map((pivot) => ({
        value: pivot,
        label: pivot,
      })),
      tags: playbookConfig.tags.map((tag) => ({
        value: tag,
        label: <JobTag tag={tag} />,
      })),
      tlp: playbookConfig.tlp,
      scan_mode: `${playbookConfig.scan_mode}`,
      scan_check_time: parseScanCheckTime(playbookConfig.scan_check_time),
      runtime_configuration: playbookConfig.runtime_configuration,
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

      if (!values.description) {
        errors.description = "This field is required.";
      }
      if (values.type.length === 0) {
        errors.type = "This field is required.";
      }

      if (values.analyzers.length === 0 && values.connectors.length === 0) {
        errors.analyzers = "analyzers or connectors required";
        errors.connectors = "analyzers or connectors required";
      }
      if (!TlpChoices.includes(values.tlp)) {
        errors.tlp = "Invalid choice";
      }

      console.debug("formik validation errors");
      console.debug(errors);
      return errors;
    },
    onSubmit: async () => {
      const response = await editPlaybookConfig(
        formik.initialValues.name,
        formik.values,
      );

      if (response?.success) {
        formik.setSubmitting(false);
        setResponseError(null);
        toggle(false);
      } else {
        setResponseError(response?.error);
      }
    },
  });

  console.debug("Edit Playbook Config - formik");
  console.debug(formik);

  const [selectedPluginsParams, editableConfig] = runtimeConfigurationParam(
    formik,
    analyzers,
    connectors,
    visualizers,
    pivots,
  );

  React.useEffect(() => {
    saveRuntimeConfiguration(
      formik,
      jsonInput,
      selectedPluginsParams,
      editableConfig,
    );
  }, [jsonInput]);

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

  return (
    <FormikProvider value={formik}>
      <Form onSubmit={formik.handleSubmit}>
        {formik.touched.name && formik.errors.name && (
          <small className="text-danger">Name: {formik.errors.name}</small>
        )}
        <FormGroup className="d-flex align-items-center">
          <Label className="me-2 mb-0" for="playbook-name">
            Name:
          </Label>
          <Input
            id="playbook-name"
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
          <Label className="me-2 mb-0" for="playbook-description">
            Description:
          </Label>
          <Input
            id="playbook-description"
            type="text"
            name="description"
            value={formik.values.description}
            onBlur={formik.handleBlur}
            onChange={formik.handleChange}
            valid={!formik.errors.description && formik.touched.description}
            invalid={formik.touched.description && formik.errors.description}
            className="bg-darker border-0"
            style={{
              minHeight: "100px",
              overflowX: "scroll",
            }}
          />
        </FormGroup>
        {formik.touched.type && formik.errors.type && (
          <small className="text-danger">Type: {formik.errors.type}</small>
        )}
        <FormGroup>
          <Label className="me-4 mb-0" for="supportedType">
            Supported types:
          </Label>
          {Object.values(AllPluginSupportedTypes).map((type) => (
            <FormGroup check inline key={`supportedType__${type}`}>
              <Input
                id={`supportedType__${type}`}
                type="checkbox"
                name="type"
                value={type}
                checked={formik.values.type.includes(type)}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
              />
              <Label check>{type}</Label>
            </FormGroup>
          ))}
        </FormGroup>
        <FormGroup row className="d-flex align-items-center">
          <Label className="me-2 mb-0" for="playbook-analyzers">
            Analyzers:
          </Label>
          <AnalyzersMultiSelectDropdownInput formik={formik} />
        </FormGroup>
        <FormGroup row className="d-flex align-items-center">
          <Label className="me-2 mb-0" for="playbook-connectors">
            Connectors:
          </Label>
          <ConnectorsMultiSelectDropdownInput formik={formik} />
        </FormGroup>
        <FormGroup row className="d-flex align-items-center">
          <Label className="me-2 mb-0" for="playbook-visualizers">
            Visualizers:
          </Label>
          <VisualizersMultiSelectDropdownInput formik={formik} />
        </FormGroup>
        <FormGroup row className="d-flex align-items-center">
          <Label className="me-2 mb-0" for="playbook-pivots">
            Pivots:
          </Label>
          <PivotsMultiSelectDropdownInput formik={formik} />
        </FormGroup>
        <FormGroup className="d-flex">
          <TLPSelectInputLabel size={1} />
          <TLPSelectInput formik={formik} />
        </FormGroup>
        <FormGroup row className="d-flex align-items-center">
          <Label className="me-2 mb-0" for="playbook-tags">
            Tags:
          </Label>
          <TagSelectInput
            id="playbook-tagselectinput"
            selectedTags={formik.values.tags}
            setSelectedTags={(selectedTags) =>
              formik.setFieldValue("tags", selectedTags, false)
            }
          />
        </FormGroup>
        <FormGroup row className="d-flex align-items-center">
          <Label className="me-2 mb-0" for="playbook-scan-config">
            Scan Configuration:
          </Label>
          <ScanConfigSelectInput formik={formik} />
        </FormGroup>
        <FormGroup row className="d-flex align-items-center">
          <Label className="me-2 mb-0" for="playbook-scan-config">
            Runtime Configuration:
          </Label>
          <EditRuntimeConfiguration
            setJsonInput={setJsonInput}
            selectedPluginsParams={selectedPluginsParams}
            editableConfig={editableConfig}
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
            disabled={!formik.dirty || !formik.isValid || formik.isSubmitting}
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
  );
}

EditPlaybookConfigForm.propTypes = {
  playbookConfig: PropTypes.object.isRequired,
  toggle: PropTypes.func.isRequired,
};
