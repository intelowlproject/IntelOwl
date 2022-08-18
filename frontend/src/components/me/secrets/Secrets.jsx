import React from "react";
import { Container } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import { PluginData } from "../../misc/PluginData";
import {
  createCustomConfig,
  PLUGIN_SECRETS_URI,
  deleteCustomConfig,
  updateCustomConfig,
} from "./api";

export default function Secrets() {
  console.debug("Secrets rendered!");

  useTitle("IntelOwl | Secrets", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      <h4>Plugin Secrets</h4>
      <PluginData
        createPluginData={createCustomConfig}
        updatePluginData={updateCustomConfig}
        deletePluginData={deleteCustomConfig}
        dataName="secrets"
        valueType="str"
        dataUri={PLUGIN_SECRETS_URI}
      />
    </Container>
  );
}
