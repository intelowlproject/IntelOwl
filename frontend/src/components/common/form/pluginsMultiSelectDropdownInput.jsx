import React from "react";
import PropTypes from "prop-types";
import ReactSelect from "react-select";

import {
  Loader,
  MultiSelectDropdownInput,
  selectStyles,
} from "@certego/certego-ui";

import { markdownToHtml } from "../markdownToHtml";
import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { JobTypes } from "../../../constants/jobConst";
import { JobTag } from "../JobTag";

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
    // case 1: scan page (classification in formik)
    if (formik.values.classification)
      return dropdownOptions(analyzersGrouped[formik.values.classification]);
    // case 2: editing/creating playbook config (no classification in formik)
    if (formik.values.type) {
      const multipleSupportedTypes = [
        ...new Set(
          formik.values.type.map((type) => analyzersGrouped[type]).flat(),
        ),
      ];
      return dropdownOptions(multipleSupportedTypes);
    }
    // case 3: creating pivot config (no classification or type in formik)
    return dropdownOptions(analyzers);
  }, [
    analyzersGrouped,
    formik.values.classification,
    formik.values.type,
    analyzers,
  ]);

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

const playbooksGrouped = (playbooks, organizationPluginsState) => {
  const grouped = {
    ip: [],
    hash: [],
    domain: [],
    url: [],
    generic: [],
    file: [],
  };
  playbooks.forEach((obj) => {
    // filter on basis of type if the playbook is not disabled in org
    if (organizationPluginsState[obj.name] === undefined) {
      obj.type.forEach((clsfn) => grouped[clsfn].push(obj));
    }
  });
  console.debug("Playbooks", grouped);
  return grouped;
};

export const playbookOptions = (
  playbooks,
  classification = null,
  organizationPluginsState = {},
) => {
  const playbooksOptionsGrouped = classification
    ? playbooksGrouped(playbooks, organizationPluginsState)[classification]
    : playbooks;

  return playbooksOptionsGrouped
    .map((playbook) => ({
      isDisabled: playbook.disabled,
      starting: playbook.starting,
      value: playbook.name,
      analyzers: playbook.analyzers,
      connectors: playbook.connectors,
      visualizers: playbook.visualizers,
      pivots: playbook.pivots,
      label: (
        <div className="d-flex justify-content-start align-items-start flex-column">
          <div className="d-flex justify-content-start align-items-baseline flex-column">
            <div>{playbook.name}&nbsp;</div>
            <div className="small text-left text-muted">
              {markdownToHtml(playbook.description)}
            </div>
          </div>
        </div>
      ),
      labelDisplay: playbook.name,
      tags: playbook.tags.map((tag) => ({
        value: tag,
        label: <JobTag tag={tag} />,
      })),
      tlp: playbook.tlp,
      scan_mode: `${playbook.scan_mode}`,
      scan_check_time: playbook.scan_check_time,
      runtime_configuration: playbook.runtime_configuration,
    }))
    .filter((item) => !item.isDisabled && item.starting);
};

export function PlaybookMultiSelectDropdownInput(props) {
  const { formik, onChange } = props;
  console.debug("PlaybookMultiSelectDropdownInput - formik:");
  console.debug(formik);

  // API/ store
  const { pluginsState: organizationPluginsState } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        pluginsState: state.pluginsState,
      }),
      [],
    ),
  );

  const [playbooksLoading, playbooksError, playbooks] =
    usePluginConfigurationStore((state) => [
      state.playbooksLoading,
      state.playbooksError,
      state.playbooks,
    ]);

  const dropdownPlaybookOptions = React.useMemo(() => {
    // case 1: scan page (classification in formik)
    if (formik.values.classification)
      return playbookOptions(
        playbooks,
        formik.values.classification,
        organizationPluginsState,
      );
    // case 2: creating pivot config (no classification in formik)
    return playbookOptions(playbooks, null, organizationPluginsState);
  }, [playbooks, formik.values.classification, organizationPluginsState]);

  return (
    <Loader
      loading={playbooksLoading}
      error={playbooksError}
      render={() => (
        <ReactSelect
          isClearable={false}
          options={dropdownPlaybookOptions}
          styles={selectStyles}
          value={formik.values.playbook}
          onChange={(selectedPlaybook) => onChange(selectedPlaybook)}
        />
      )}
    />
  );
}

PlaybookMultiSelectDropdownInput.propTypes = {
  formik: PropTypes.object.isRequired,
  onChange: PropTypes.func.isRequired,
};
