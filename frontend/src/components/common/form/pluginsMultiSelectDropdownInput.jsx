import React from "react";
import PropTypes from "prop-types";

import { Loader, MultiSelectDropdownInput } from "@certego/certego-ui";

import { markdownToHtml } from "../markdownToHtml";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { JobTypes } from "../../../constants/jobConst";

function dropdownOptions(plugins) {
  return plugins
    ?.map((plugin) => ({
      isDisabled: !plugin.verification.configured || plugin.disabled,
      value: plugin.name,
      label: (
        <div
          id={`${plugin.type}-${plugin.name}`}
          className="d-flex justify-content-start align-items-start flex-column"
        >
          <div className="d-flex justify-content-start align-items-baseline flex-column">
            <div>{plugin.name}&nbsp;</div>
            <div className="small text-start text-muted">
              {markdownToHtml(plugin.description)}
            </div>
          </div>
          {!plugin.verification.configured && (
            <div className="small text-danger">
              ⚠ {plugin.verification.details}
            </div>
          )}
        </div>
      ),
      labelDisplay: plugin.name,
    }))
    .sort((currentPlugin, nextPlugin) =>
      // eslint-disable-next-line no-nested-ternary
      currentPlugin.isDisabled === nextPlugin.isDisabled
        ? 0
        : currentPlugin.isDisabled
          ? 1
          : -1,
    );
}

export function AnalyzersMultiSelectDropdownInput(props) {
  const { formik } = props;
  console.debug("AnalyzersMultiSelectDropdownInput - formik:");
  console.debug(formik);

  // API/ store
  const [analyzersLoading, analyzersError, analyzers] =
    usePluginConfigurationStore((state) => [
      state.analyzersLoading,
      state.analyzersError,
      state.analyzers,
    ]);

  const analyzersGrouped = React.useMemo(() => {
    const grouped = {
      ip: [],
      hash: [],
      domain: [],
      url: [],
      generic: [],
      file: [],
    };
    analyzers.forEach((obj) => {
      if (obj.type === JobTypes.FILE) {
        grouped.file.push(obj);
      } else {
        obj.observable_supported.forEach((clsfn) => grouped[clsfn].push(obj));
      }
    });
    return grouped;
  }, [analyzers]);

  const analyzersOptions = React.useMemo(() => {
    // case 1: scan page
    if (formik.values.classification)
      return dropdownOptions(analyzersGrouped[formik.values.classification]);
    // case 2: editing playbook config (no classification in formik)
    const multipleSupportedTypes = [
      ...new Set(
        formik.values.type.map((type) => analyzersGrouped[type]).flat(),
      ),
    ];
    return dropdownOptions(multipleSupportedTypes);
  }, [analyzersGrouped, formik.values.classification, formik.values.type]);

  return (
    <Loader
      loading={analyzersLoading}
      error={analyzersError}
      render={() => (
        <MultiSelectDropdownInput
          options={analyzersOptions}
          value={formik.values.analyzers}
          onChange={(value) => formik.setFieldValue("analyzers", value, false)}
        />
      )}
    />
  );
}

AnalyzersMultiSelectDropdownInput.propTypes = {
  formik: PropTypes.object.isRequired,
};

export function ConnectorsMultiSelectDropdownInput({ formik }) {
  console.debug("ConnectorsMultiSelectDropdownInput - formik:");
  console.debug(formik);

  // API/ store
  const [connectorsLoading, connectorsError, connectors] =
    usePluginConfigurationStore((state) => [
      state.connectorsLoading,
      state.connectorsError,
      state.connectors,
    ]);

  const connectorOptions = React.useMemo(
    () => dropdownOptions(connectors),
    [connectors],
  );

  return (
    <Loader
      loading={connectorsLoading}
      error={connectorsError}
      render={() => (
        <MultiSelectDropdownInput
          options={connectorOptions}
          value={formik.values.connectors}
          onChange={(value) => formik.setFieldValue("connectors", value, false)}
        />
      )}
    />
  );
}

ConnectorsMultiSelectDropdownInput.propTypes = {
  formik: PropTypes.object.isRequired,
};

export function VisualizersMultiSelectDropdownInput({ formik }) {
  console.debug("VisualizersMultiSelectDropdownInput - formik:");
  console.debug(formik);

  // API/ store
  const [visualizersLoading, visualizersError, visualizers] =
    usePluginConfigurationStore((state) => [
      state.visualizersLoading,
      state.visualizersError,
      state.visualizers,
    ]);

  const visualizerOptions = React.useMemo(
    () => dropdownOptions(visualizers),
    [visualizers],
  );

  return (
    <Loader
      loading={visualizersLoading}
      error={visualizersError}
      render={() => (
        <MultiSelectDropdownInput
          options={visualizerOptions}
          value={formik.values.visualizers}
          onChange={(value) =>
            formik.setFieldValue("visualizers", value, false)
          }
        />
      )}
    />
  );
}

VisualizersMultiSelectDropdownInput.propTypes = {
  formik: PropTypes.object.isRequired,
};

export function PivotsMultiSelectDropdownInput({ formik }) {
  console.debug("PivotsMultiSelectDropdownInput - formik:");
  console.debug(formik);

  // API/ store
  const [pivotsLoading, pivotsError, pivots] = usePluginConfigurationStore(
    (state) => [state.pivotsLoading, state.pivotsError, state.pivots],
  );

  const pivotOptions = React.useMemo(() => dropdownOptions(pivots), [pivots]);

  return (
    <Loader
      loading={pivotsLoading}
      error={pivotsError}
      render={() => (
        <MultiSelectDropdownInput
          options={pivotOptions}
          value={formik.values.pivots}
          onChange={(value) => formik.setFieldValue("pivots", value, false)}
        />
      )}
    />
  );
}

PivotsMultiSelectDropdownInput.propTypes = {
  formik: PropTypes.object.isRequired,
};
