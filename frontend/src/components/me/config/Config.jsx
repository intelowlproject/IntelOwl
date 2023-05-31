import PropTypes from "prop-types";
import React from "react";
import { PluginData } from "../../misc/PluginData";
import { PLUGIN_CONFIG_URI } from "./api";

/**
 * This component wrap the table with the plugins configuration.
 * Based on the values of this config the table will show data about params or secrets.
 *
 * @param {function} configFilter function used to filter the plugins received by the backend
 * @param {object} additionalConfigData contains a value used to show the values of the configuration or hide (***) in case of secrets
 * @param {string} dataName name of the configuration fileds (params/secrets)
 * @param {boolean} editable flag to chose if the user can edit the params (used by the org section)
 * @returns {PluginData} element with the configurations
 */
export default function Config({
  configFilter,
  additionalConfigData,
  dataName,
  editable,
}) {
  return (
    <PluginData
      dataName={dataName}
      valueType="json"
      dataUri={PLUGIN_CONFIG_URI}
      entryFilter={configFilter}
      additionalEntryData={additionalConfigData}
      editable={editable}
    />
  );
}

Config.propTypes = {
  additionalConfigData: PropTypes.object,
  configFilter: PropTypes.func.isRequired,
  dataName: PropTypes.string.isRequired,
  editable: PropTypes.bool.isRequired,
};

Config.defaultProps = {
  additionalConfigData: {},
};
