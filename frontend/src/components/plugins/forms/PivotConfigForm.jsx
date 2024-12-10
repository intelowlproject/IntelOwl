import React from "react";
import {
  FormGroup,
  Label,
  Button,
  Spinner,
  Input,
  UncontrolledTooltip,
} from "reactstrap";
import { Form, useFormik, FormikProvider } from "formik";
import PropTypes from "prop-types";
import ReactSelect from "react-select";
import { MdInfoOutline } from "react-icons/md";
import { selectStyles } from "@certego/certego-ui";

import {
  PlaybookMultiSelectDropdownInput,
  AnalyzersMultiSelectDropdownInput,
  ConnectorsMultiSelectDropdownInput,
} from "../../common/form/pluginsMultiSelectDropdownInput";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { PluginsTypes } from "../../../constants/pluginConst";
import {
  editConfiguration,
  createConfiguration,
  editPluginConfig,
  createPluginConfig,
} from "../pluginsApi";

export function PivotConfigForm({ pivotConfig, toggle, isEditing }) {
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
              first successful analyzers or connectors.
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

  const isPythonModuleSelectable = pythonModuleOptions.find(
    (element) => element.value === pivotConfig?.python_module,
  );

  const formik = useFormik({
    initialValues: {
      name: pivotConfig?.name || "",
      description: pivotConfig?.description || "<generated automatically>",
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
      analyzers:
        pivotConfig?.related_analyzer_configs?.map((analyzer) => ({
          value: analyzer,
          label: analyzer,
        })) || [],
      connectors:
        pivotConfig?.related_connector_configs?.map((connector) => ({
          value: connector,
          label: connector,
        })) || [],
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

      if (values.analyzers.length === 0 && values.connectors.length === 0) {
        errors.analyzers = "Analyzers or connectors required";
        errors.connectors = "Analyzers or connectors required";
      }
      if (values.analyzers.length !== 0 && values.connectors.length !== 0) {
        errors.analyzers = "You can't set both analyzers and connectors";
        errors.connectors = "You can't set both analyzers and connectors";
      }

      console.debug("formik validation errors");
      console.debug(errors);
      return errors;
    },
    onSubmit: async () => {
      let response;
      let responsePluginConfig = { success: true, error: null };

      const payloadData = {
        name: formik.values.name,
        python_module: formik.values.python_module.value,
        playbooks_choice: [formik.values.playbook[0].value],
        related_analyzer_configs: formik.values.analyzers.map(
          (analyzer) => analyzer.value,
        ),
        related_connector_configs: formik.values.connectors.map(
          (connector) => connector.value,
        ),
      };

      if (isEditing) {
        const pivotToEdit =
          formik.initialValues.name !== formik.values.name
            ? formik.initialValues.name
            : formik.values.name;
        response = await editConfiguration(
          PluginsTypes.PIVOT,
          pivotToEdit,
          payloadData,
        );
      } else {
        response = await createConfiguration(PluginsTypes.PIVOT, payloadData);
      }

      // plugin config
      if (response?.success && formik.values.field_to_compare) {
        const pluginConfig = {
          attribute: "field_to_compare",
          value: formik.values.field_to_compare,
          parameter: response.data.parameters.field_to_compare.id,
        };
        if (isEditing) {
          responsePluginConfig = await editPluginConfig(
            PluginsTypes.PIVOT,
            formik.values.name,
            [pluginConfig],
          );
        } else {
          pluginConfig.pivot_config = formik.values.name;
          pluginConfig.for_organization = false;
          responsePluginConfig = await createPluginConfig(
            PluginsTypes.PIVOT,
            formik.values.name,
            [pluginConfig],
          );
        }
      }

      if (response?.success && responsePluginConfig?.success) {
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

  return (
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
            className="me-2 mb-0 d-flex"
            for="pivot-description"
            style={{ minWidth: "15%" }}
          >
            Description:
            <div className="ms-2">
              <MdInfoOutline id="pivot-description-infoicon" fontSize="20" />
              <UncontrolledTooltip
                trigger="hover"
                target="pivot-description-infoicon"
                placement="right"
                fade={false}
                innerClassName="p-2 text-start text-nowrap md-fit-content"
              >
                The description is automatically generated based on the
                configuration.
              </UncontrolledTooltip>
            </div>
          </Label>
          <Input
            id="pivot-description"
            type="textarea"
            name="description"
            value={formik.values.description}
            onBlur={formik.handleBlur}
            onChange={formik.handleChange}
            valid={!formik.errors.description && formik.touched.description}
            invalid={formik.touched.description && formik.errors.description}
            className="bg-darker border-0 text-gray"
            style={{
              minHeight: "100px",
              overflowX: "scroll",
              cursor: "not-allowed",
            }}
            disabled
          />
        </FormGroup>
        <div className="bg-tertiary py-2 px-3 rounded">
          <strong>Note:</strong> Pivots are designed to create a job from
          another job after certain conditions are triggered. <br />
          This plugin can only run automatically within a playbook so it is
          important to select the analyzers or connectors after which the pivot
          will be executed. <br />
          Every playbook containing the following combination of
          analyzers/connectors can have this Pivot attached to.
        </div>
        <div className="py-4">
          {formik.values.analyzers.length !== 0 &&
            formik.values.connectors.length !== 0 && (
              <>
                <br />
                <small className="text-danger">{formik.errors.analyzers}</small>
              </>
            )}
          <FormGroup row className="d-flex align-items-center">
            <Label className="me-2 mb-0" for="pivot-analyzers">
              Analyzers:
            </Label>
            <AnalyzersMultiSelectDropdownInput formik={formik} />
          </FormGroup>
          <FormGroup row className="d-flex align-items-center">
            <Label className="me-2 mb-0" for="pivot-connectors">
              Connectors:
            </Label>
            <ConnectorsMultiSelectDropdownInput formik={formik} />
          </FormGroup>
        </div>
        <FormGroup
          className={`d-flex align-items-center ${
            isEditing && !isPythonModuleSelectable ? "" : "row"
          }`}
        >
          <Label
            className="me-2 mb-0"
            for="pivot-type"
            style={{ minWidth: "15%" }}
          >
            Type of pivot:
          </Label>
          {isEditing && !isPythonModuleSelectable ? (
            <Input
              id="pivot-type"
              type="text"
              name="python_module"
              value={formik.values.python_module.value}
              disabled
              className="bg-darker border-0 text-gray"
              style={{ cursor: "not-allowed" }}
            />
          ) : (
            <ReactSelect
              isClearable={false}
              options={pythonModuleOptions}
              styles={selectStyles}
              value={formik.values.python_module}
              onChange={(value) =>
                formik.setFieldValue("python_module", value, false)
              }
            />
          )}
        </FormGroup>
        {formik.values.python_module.value === "any_compare.AnyCompare" && (
          <FormGroup className="d-flex align-items-center">
            <Label
              className="me-2 mb-0"
              for="pivot-field-to-compare"
              style={{ minWidth: "45%" }}
            >
              Dotted path to the field that will be extracted and then analyzed:
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

PivotConfigForm.propTypes = {
  pivotConfig: PropTypes.object,
  toggle: PropTypes.func.isRequired,
  isEditing: PropTypes.bool.isRequired,
};

PivotConfigForm.defaultProps = {
  pivotConfig: {},
};
