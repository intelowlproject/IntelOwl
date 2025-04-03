import React from "react";
import { FormGroup, Label, Button, Spinner, Input } from "reactstrap";
import { Form, useFormik, FormikProvider } from "formik";
import PropTypes from "prop-types";
import {
  IoIosArrowDropdownCircle,
  IoIosArrowDropupCircle,
} from "react-icons/io";

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
import {
  AllPluginSupportedTypes,
  PluginsTypes,
} from "../../../constants/pluginConst";
import { ScanConfigSelectInput } from "../../common/form/ScanConfigSelectInput";
import { parseScanCheckTime } from "../../../utils/time";
import { TagSelectInput } from "../../common/form/TagSelectInput";
import { JobTag } from "../../common/JobTag";
import {
  TlpChoices,
  TLPs,
  ScanModesNumeric,
} from "../../../constants/advancedSettingsConst";
import {
  EditRuntimeConfiguration,
  runtimeConfigurationParam,
  saveRuntimeConfiguration,
} from "../../common/form/runtimeConfigurationInput";
import { editConfiguration, createConfiguration } from "../pluginsApi";

// constants
const stateSelector = (state) => [
  state.analyzers,
  state.connectors,
  state.visualizers,
  state.pivots,
  state.retrievePlaybooksConfiguration,
  state.analyzersLoading,
  state.connectorsLoading,
  state.visualizersLoading,
  state.pivotsLoading,
];

export function PlaybookConfigForm({ playbookConfig, toggle, isEditing }) {
  console.debug("PlaybookConfigForm rendered!");

  // states
  const [selectedPluginsParams, setSelectedPluginsParams] = React.useState({});
  const [editableConfig, setEditableConfig] = React.useState({});
  const [jsonInput, setJsonInput] = React.useState({});
  const [responseError, setResponseError] = React.useState(null);

  // This state is necessary because the runtime config JSON editor does not work correctly due to useEffects in this component
  const [isRuntimeConfigOpen, setIsRuntimeConfigOpen] = React.useState(false);

  // store
  const [
    analyzers,
    connectors,
    visualizers,
    pivots,
    retrievePlaybooksConfiguration,
    analyzersLoading,
    connectorsLoading,
    visualizersLoading,
    pivotsLoading,
  ] = usePluginConfigurationStore(stateSelector);

  const pluginsLoading =
    analyzersLoading ||
    connectorsLoading ||
    visualizersLoading ||
    pivotsLoading;

  const formik = useFormik({
    initialValues: {
      name: playbookConfig?.name || "",
      description: playbookConfig?.description || "",
      type: playbookConfig?.type || [],
      analyzers:
        playbookConfig?.analyzers?.map((analyzer) => ({
          value: analyzer,
          label: analyzer,
        })) || [],
      connectors:
        playbookConfig?.connectors?.map((connector) => ({
          value: connector,
          label: connector,
        })) || [],
      visualizers:
        playbookConfig?.visualizers?.map((visualizer) => ({
          value: visualizer,
          label: visualizer,
        })) || [],
      pivots:
        playbookConfig?.pivots?.map((pivot) => ({
          value: pivot,
          label: pivot,
        })) || [],
      tags:
        playbookConfig?.tags?.map((tag) => ({
          value: tag,
          label: <JobTag tag={tag} />,
        })) || [],
      tlp: playbookConfig?.tlp || TLPs.AMBER,
      scan_mode: playbookConfig?.scan_mode
        ? `${playbookConfig?.scan_mode}`
        : ScanModesNumeric.CHECK_PREVIOUS_ANALYSIS,
      scan_check_time: parseScanCheckTime(
        playbookConfig?.scan_check_time || "01:00:00:00",
      ),
      runtime_configuration: playbookConfig?.runtime_configuration || {
        analyzers: {},
        connectors: {},
        pivots: {},
        visualizers: {},
      },
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
      let response;
      const payloadData = {
        name: formik.values.name,
        description: formik.values.description,
        type: formik.values.type,
        analyzers: formik.values.analyzers.map((analyzer) => analyzer.value),
        connectors: formik.values.connectors.map(
          (connector) => connector.value,
        ),
        visualizers: formik.values.visualizers.map(
          (visualizer) => visualizer.value,
        ),
        pivots: formik.values.pivots.map((pivot) => pivot.value),
        runtime_configuration: formik.values.runtime_configuration,
        tags_labels: formik.values.tags.map((tag) => tag.value.label),
        tlp: formik.values.tlp,
        scan_mode: parseInt(formik.values.scan_mode, 10),
        scan_check_time: null,
      };
      if (
        formik.values.scan_mode === ScanModesNumeric.CHECK_PREVIOUS_ANALYSIS
      ) {
        payloadData.scan_check_time = `${formik.values.scan_check_time}:00:00`;
      }

      if (isEditing) {
        const playbookToEdit =
          formik.initialValues.name !== formik.values.name
            ? formik.initialValues.name
            : formik.values.name;
        response = await editConfiguration(
          PluginsTypes.PLAYBOOK,
          playbookToEdit,
          payloadData,
        );
      } else {
        response = await createConfiguration(
          PluginsTypes.PLAYBOOK,
          payloadData,
        );
      }

      if (response?.success) {
        formik.setSubmitting(false);
        setResponseError(null);
        formik.resetForm();
        toggle(false);
        retrievePlaybooksConfiguration();
      } else {
        setResponseError(response?.error);
      }
    },
  });

  console.debug("Playbook Config - formik");
  console.debug(formik);

  React.useEffect(() => {
    if (!pluginsLoading) {
      // close the config dropdown before updating the plugins otherwise the new config is not loaded correctly
      setIsRuntimeConfigOpen(false);
      const [params, config] = runtimeConfigurationParam(
        formik,
        analyzers,
        connectors,
        visualizers,
        pivots,
      );
      setSelectedPluginsParams(params);
      setEditableConfig(config);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    formik.values.analyzers,
    formik.values.connectors,
    formik.values.pivots,
    formik.values.visualizers,
    pluginsLoading,
  ]);

  React.useEffect(() => {
    saveRuntimeConfiguration(
      formik,
      jsonInput,
      selectedPluginsParams,
      editableConfig,
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
            type="textarea"
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
        {/* The runtime config has been included in a dropdown to ensure that 
          it correctly renders the config once it is modified by the component's useEffect
        */}
        <Button
          size="sm"
          onClick={() => setIsRuntimeConfigOpen(!isRuntimeConfigOpen)}
          color="primary"
          className="my-2"
        >
          <span className="me-1">Runtime Configuration</span>
          {isRuntimeConfigOpen ? (
            <IoIosArrowDropupCircle />
          ) : (
            <IoIosArrowDropdownCircle />
          )}
        </Button>
        {isRuntimeConfigOpen && (
          <FormGroup row className="d-flex align-items-center">
            <EditRuntimeConfiguration
              setJsonInput={setJsonInput}
              selectedPluginsParams={selectedPluginsParams}
              editableConfig={editableConfig}
            />
          </FormGroup>
        )}
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

PlaybookConfigForm.propTypes = {
  playbookConfig: PropTypes.object,
  toggle: PropTypes.func.isRequired,
  isEditing: PropTypes.bool.isRequired,
};

PlaybookConfigForm.defaultProps = {
  playbookConfig: {},
};
