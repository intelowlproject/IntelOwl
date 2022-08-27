import PropTypes from "prop-types";
import React from "react";
import { PluginData } from "../../misc/PluginData";
import {
  createCustomConfig,
  PLUGIN_CONFIG_URI,
  deleteCustomConfig,
  updateCustomConfig,
} from "./api";

export default function Config({ configFilter, additionalConfigData }) {
  return (
    <PluginData
      createPluginData={createCustomConfig}
      updatePluginData={updateCustomConfig}
      deletePluginData={deleteCustomConfig}
      dataName="params"
      valueType="json"
      dataUri={PLUGIN_CONFIG_URI}
      entryFilter={configFilter}
      additionalEntryData={additionalConfigData}
    />
  );
}

Config.propTypes = {
  additionalConfigData: PropTypes.object,
  configFilter: PropTypes.func.isRequired,
};

Config.defaultProps = {
  additionalConfigData: {},
};
