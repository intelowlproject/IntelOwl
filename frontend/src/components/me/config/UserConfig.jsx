import PropTypes from "prop-types";
import React from "react";
import { Container } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import { PluginData } from "../../misc/PluginData";
import {
  createCustomConfig,
  CUSTOM_CONFIG_URI,
  deleteCustomConfig,
  updateCustomConfig,
} from "./api";

export function Config({ configFilter, additionalConfigData }) {
  return (
    <PluginData
      createPluginData={createCustomConfig}
      updatePluginData={updateCustomConfig}
      deletePluginData={deleteCustomConfig}
      dataName="params"
      valueType="json"
      dataUri={CUSTOM_CONFIG_URI}
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

export default function UserConfig() {
  console.debug("Config rendered!");

  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      <h4>Your custom configuration</h4>
      <Config
        configFilter={(resp) => resp.filter((item) => !item.organization)}
      />
    </Container>
  );
}
